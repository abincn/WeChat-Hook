// wxcx_verify.cpp - executable-section integrity baseline / diff
//
// Only executable sections are hashed: .data and friends change with runtime
// state and would drown the signal.
//
// NOTE: MSVC forbids __try in a function that needs C++ object unwinding
// (C2712), so every structured-exception read is isolated in a small POD-only
// helper below.

#include "wxcx_verify.h"

#include "httplib.h"
#include "json.hpp"

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "global.h"

using json = nlohmann::json;

namespace wxcx
{
namespace verify
{
namespace
{
    constexpr size_t kBlock = 4096;
    constexpr uint64_t kSysmsgRva = 0x22D07C0;
    constexpr size_t   kSysmsgLen = 9;
    static const uint8_t kSysmsgOriginal[9] = {
        0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54
    };

    struct Section
    {
        std::string name;
        uint64_t    va = 0;
        uint64_t    size = 0;
    };

    struct Baseline
    {
        bool valid = false;
        uint64_t takenAt = 0;
        std::vector<Section> sections;
        std::vector<std::vector<uint32_t>> blocks;
    };

    std::mutex g_mtx;
    Baseline   g_base;

    // ---------------------------------------------------------- POD-only SEH
    bool SafeCopy(const void* src, void* dst, size_t n)
    {
        __try
        {
            memcpy(dst, src, n);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool SafeReadU32(const void* p, uint32_t& out)
    {
        __try
        {
            out = *(const uint32_t*)p;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool SafeReadU16(const void* p, uint16_t& out)
    {
        __try
        {
            out = *(const uint16_t*)p;
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    // ---------------------------------------------------------------- CRC32
    uint32_t Crc32(const uint8_t* p, size_t n)
    {
        static uint32_t table[256];
        static bool init = false;
        if (!init)
        {
            for (uint32_t i = 0; i < 256; ++i)
            {
                uint32_t c = i;
                for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                table[i] = c;
            }
            init = true;
        }
        uint32_t crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < n; ++i) crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }

    // 单块读取 + CRC（缓冲区静态，函数内无 C++ 对象）
    uint32_t BlockCrc(const uint8_t* src, size_t len)
    {
        static uint8_t buf[kBlock];
        if (len > kBlock) len = kBlock;
        if (!SafeCopy(src, buf, len)) return 0xDEADBEEFu;
        return Crc32(buf, len);
    }

    // ---------------------------------------------------------- 节表枚举
    struct RawSec
    {
        char     name[9];
        uint32_t va;
        uint32_t vsize;
        uint32_t chars;
    };

    bool ReadSectionTable(RawSec* out, uint32_t maxOut, uint32_t& count)
    {
        count = 0;
        if (!g_hWeixinDll) return false;

        const uint8_t* base = (const uint8_t*)g_hWeixinDll;
        uint32_t e_lfanew = 0;
        uint32_t sig = 0;
        if (!SafeReadU32(base + 0x3C, e_lfanew)) return false;
        if (!SafeReadU32(base + e_lfanew, sig)) return false;
        if (sig != 0x00004550) return false;

        uint16_t nsec = 0, optsz = 0;
        if (!SafeReadU16(base + e_lfanew + 4 + 2, nsec)) return false;
        if (!SafeReadU16(base + e_lfanew + 4 + 16, optsz)) return false;
        if (nsec > maxOut) nsec = (uint16_t)maxOut;

        const uint8_t* sec = base + e_lfanew + 4 + 20 + optsz;
        for (uint16_t i = 0; i < nsec; ++i, sec += 40)
        {
            RawSec r{};
            if (!SafeCopy(sec, r.name, 8)) return false;
            if (!SafeReadU32(sec + 8, r.vsize)) return false;
            if (!SafeReadU32(sec + 12, r.va)) return false;
            if (!SafeReadU32(sec + 36, r.chars)) return false;
            out[count++] = r;
        }
        return true;
    }

    bool EnumerateExecSections(std::vector<Section>& out)
    {
        RawSec raw[96] = {};
        uint32_t n = 0;
        if (!ReadSectionTable(raw, 96, n)) return false;

        for (uint32_t i = 0; i < n; ++i)
        {
            if (!(raw[i].chars & 0x20000000)) continue;   // IMAGE_SCN_MEM_EXECUTE
            if (raw[i].vsize == 0) continue;
            Section s;
            s.name = raw[i].name;
            s.va = raw[i].va;
            s.size = raw[i].vsize;
            out.push_back(s);
        }
        return !out.empty();
    }

    // ---------------------------------------------------------------- 基线
    std::string HexRva(uint64_t v)
    {
        char b[32] = { 0 };
        snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v);
        return std::string(b);
    }

    bool HashSections(const std::vector<Section>& secs,
                      std::vector<std::vector<uint32_t>>& blocks,
                      json& perSection)
    {
        if (!g_hWeixinDll) return false;
        const uint8_t* base = (const uint8_t*)g_hWeixinDll;
        blocks.clear();
        perSection = json::array();

        for (const auto& s : secs)
        {
            std::vector<uint32_t> crcs;
            size_t nblocks = (size_t)((s.size + kBlock - 1) / kBlock);
            crcs.reserve(nblocks);

            for (size_t i = 0; i < nblocks; ++i)
            {
                size_t off = (size_t)s.va + i * kBlock;
                size_t len = kBlock;
                if ((i + 1) * kBlock > s.size) len = (size_t)(s.size - i * kBlock);
                crcs.push_back(BlockCrc(base + off, len));
            }

            json js;
            js["name"] = s.name;
            js["rva"] = HexRva(s.va);
            js["size"] = s.size;
            js["blocks"] = nblocks;
            perSection.push_back(js);

            blocks.push_back(std::move(crcs));
        }
        return true;
    }

    std::string PrologueState()
    {
        if (!g_hWeixinDll) return "no-module";
        const uint8_t* p = (const uint8_t*)g_hWeixinDll + kSysmsgRva;
        uint8_t cur[kSysmsgLen] = { 0 };
        if (!SafeCopy(p, cur, kSysmsgLen)) return "unreadable";

        if (memcmp(cur, kSysmsgOriginal, kSysmsgLen) == 0) return "pristine";
        if (cur[0] == 0xCC) return "patched(int3)";
        if (cur[0] == 0xE9) return "patched(e9)";
        return "modified(other)";
    }

    std::string TakeBaseline()
    {
        std::vector<Section> secs;
        if (!EnumerateExecSections(secs))
            return json{ {"ok", false}, {"reason", "cannot enumerate sections"} }.dump();

        std::vector<std::vector<uint32_t>> blocks;
        json perSection;
        if (!HashSections(secs, blocks, perSection))
            return json{ {"ok", false}, {"reason", "hash failed"} }.dump();

        std::lock_guard<std::mutex> lk(g_mtx);
        g_base.valid = true;
        g_base.takenAt = ::GetTickCount64();
        g_base.sections = secs;
        g_base.blocks = std::move(blocks);

        json out;
        out["ok"] = true;
        out["taken_ms"] = g_base.takenAt;
        out["sections"] = perSection;
        out["prologue"] = PrologueState();
        out["note"] = "compare later with /wxcx/verify/check";
        return out.dump();
    }

    std::string CheckAgainstBaseline(size_t maxDiffs)
    {
        std::vector<Section> secs;
        std::vector<std::vector<uint32_t>> baseBlocks;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            if (!g_base.valid)
                return json{ {"ok", false}, {"reason", "no baseline; POST /wxcx/verify/baseline first"} }.dump();
            secs = g_base.sections;
            baseBlocks = g_base.blocks;
        }

        std::vector<std::vector<uint32_t>> now;
        json perSection;
        if (!HashSections(secs, now, perSection))
            return json{ {"ok", false}, {"reason", "hash failed"} }.dump();

        json diffs = json::array();
        size_t totalDiff = 0;
        bool touchesPrologue = false;

        for (size_t si = 0; si < secs.size() && si < now.size(); ++si)
        {
            const auto& a = baseBlocks[si];
            const auto& b = now[si];
            for (size_t bi = 0; bi < a.size() && bi < b.size(); ++bi)
            {
                if (a[bi] == b[bi]) continue;
                uint64_t rva = secs[si].va + bi * kBlock;
                totalDiff++;
                bool covers = (rva <= kSysmsgRva && rva + kBlock > kSysmsgRva);
                if (covers) touchesPrologue = true;
                if (diffs.size() < maxDiffs)
                {
                    json d;
                    d["section"] = secs[si].name;
                    d["rva"] = HexRva(rva);
                    d["covers_sysmsg_prologue"] = covers;
                    d["before"] = a[bi];
                    d["now"] = b[bi];
                    diffs.push_back(d);
                }
            }
        }

        std::string prologue = PrologueState();

        json out;
        out["ok"] = true;
        out["equal"] = (totalDiff == 0);
        out["diff_blocks"] = totalDiff;
        out["diffs"] = diffs;
        out["prologue"] = prologue;

        if (totalDiff == 0)
            out["verdict"] = "clean: executable sections match the captured baseline byte-for-byte";
        else if (touchesPrologue && prologue != "pristine")
            out["verdict"] = "expected: only the sysmsg prologue window differs (hook still armed)";
        else
            out["verdict"] = "attention: differences outside our patch window - something else modified code";

        return out.dump();
    }
}

    std::string StatusJson()
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        json j;
        j["baseline"] = g_base.valid;
        if (g_base.valid)
        {
            j["taken_ms"] = g_base.takenAt;
            json secs = json::array();
            for (size_t i = 0; i < g_base.sections.size(); ++i)
            {
                json s;
                s["name"] = g_base.sections[i].name;
                s["rva"] = g_base.sections[i].va;
                s["size"] = g_base.sections[i].size;
                s["blocks"] = g_base.blocks[i].size();
                secs.push_back(s);
            }
            j["sections"] = secs;
        }
        j["prologue"] = PrologueState();
        j["sysmsg_rva"] = "0x22D07C0";
        return j.dump();
    }

    void RegisterRoutes(httplib::Server& svr)
    {
        svr.Get("/wxcx/verify/status", [](const httplib::Request&, httplib::Response& res)
        {
            res.set_content(StatusJson(), "application/json");
        });

        svr.Post("/wxcx/verify/baseline", [](const httplib::Request&, httplib::Response& res)
        {
            res.set_content(TakeBaseline(), "application/json");
        });

        svr.Get("/wxcx/verify/check", [](const httplib::Request& req, httplib::Response& res)
        {
            size_t maxDiffs = 50;
            if (req.has_param("max"))
            {
                try { maxDiffs = (size_t)std::stoul(req.get_param_value("max")); } catch (...) {}
                if (maxDiffs == 0 || maxDiffs > 500) maxDiffs = 50;
            }
            res.set_content(CheckAgainstBaseline(maxDiffs), "application/json");
        });
    }

} // namespace verify
} // namespace wxcx
