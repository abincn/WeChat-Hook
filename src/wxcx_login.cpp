// wxcx_login.cpp - 登录状态探测（不依赖内部偏移）
#include "wxcx_login.h"

#include "httplib.h"
#include "json.hpp"

#include <windows.h>
#include <shlobj.h>

#include <string>
#include <vector>

#include "../xdb/db_mgr.h"
#include "global.h"

using json = nlohmann::json;

namespace wxcx
{
namespace login
{
namespace
{
    std::string WideToUtf8(const std::wstring& w)
    {
        if (w.empty()) return {};
        int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string s(n > 0 ? n : 0, '\0');
        if (n > 0)
            ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
        return s;
    }

    std::wstring KnownFolder(REFKNOWNFOLDERID id)
    {
        PWSTR p = nullptr;
        std::wstring out;
        if (SUCCEEDED(::SHGetKnownFolderPath(id, 0, nullptr, &p)) && p)
        {
            out = p;
            ::CoTaskMemFree(p);
        }
        return out;
    }

    // 候选数据根目录
    std::vector<std::wstring> DataRoots()
    {
        std::vector<std::wstring> roots;
        std::wstring docs = KnownFolder(FOLDERID_Documents);
        if (!docs.empty())
        {
            roots.push_back(docs + L"\\xwechat_files");
            roots.push_back(docs + L"\\WeChat Files");
        }
        std::wstring roaming = KnownFolder(FOLDERID_RoamingAppData);
        if (!roaming.empty())
        {
            roots.push_back(roaming + L"\\Tencent\\xwechat_files");
            roots.push_back(roaming + L"\\Tencent\\WeChat Files");
        }
        return roots;
    }

    // 在根目录下找形如 wxid_xxx / xxx_xxxx 且含 db_storage 的账号目录
    bool FindAccountDir(std::wstring& outDir, std::string& outWxid)
    {
        for (const auto& root : DataRoots())
        {
            WIN32_FIND_DATAW fd{};
            std::wstring pattern = root + L"\\*";
            HANDLE h = ::FindFirstFileW(pattern.c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) continue;

            do
            {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

                std::wstring dir = root + L"\\" + fd.cFileName;
                std::wstring dbStorage = dir + L"\\db_storage";
                std::wstring msgDir = dir + L"\\msg";
                if (::GetFileAttributesW(dbStorage.c_str()) != INVALID_FILE_ATTRIBUTES ||
                    ::GetFileAttributesW(msgDir.c_str()) != INVALID_FILE_ATTRIBUTES)
                {
                    outDir = dir;
                    outWxid = WideToUtf8(fd.cFileName);
                    ::FindClose(h);
                    return true;
                }
            } while (::FindNextFileW(h, &fd));

            ::FindClose(h);
        }
        return false;
    }
}

    Probe RunProbe()
    {
        Probe p;

        // 1) 强制触发一次 DB 扫描（绕过 g_IsLogin 门禁）
        g_ScanDatabasesForced = true;
        const std::map<std::string, LPVOID>& dbs = xmgr::DatabaseMgr::getInstance().searchDatabases();
        size_t n = dbs.size();
        g_ScanDatabasesForced = false;

        p.dbCount = (int)n;
        if (n > 0)
        {
            p.ok = true;
            p.source = "db";
            std::string names;
            for (const auto& kv : dbs)
            {
                if (!names.empty()) names += ",";
                names += kv.first;
            }
            p.detail = names;
            return p;
        }

        // 2) 兜底：数据目录
        std::wstring dir;
        std::string wxid;
        if (FindAccountDir(dir, wxid))
        {
            p.ok = true;
            p.source = "datadir";
            p.wxid = wxid;
            p.dataDir = WideToUtf8(dir);
            p.detail = "account dir found (db not scanned yet)";
            return p;
        }

        p.source = "none";
        p.detail = "no sqlite handles and no account data dir";
        return p;
    }

    bool Detect(bool forceRefresh)
    {
        if (!forceRefresh && g_IsLogin == 1) return true;

        Probe p = RunProbe();
        if (p.ok)
        {
            g_IsLogin = 1;
            if (!p.wxid.empty() && SelfInfo.wxid.empty())
                SelfInfo.wxid = p.wxid;
            return true;
        }
        return false;
    }

    void RegisterRoutes(httplib::Server& svr)
    {
        // 只读探测：返回证据链，便于排查
        svr.Post("/wxcx/login/detect", [](const httplib::Request& req, httplib::Response& res)
        {
            bool force = true;
            try
            {
                if (!req.body.empty())
                {
                    json j = json::parse(req.body);
                    if (j.contains("force") && j["force"].is_boolean()) force = j["force"].get<bool>();
                }
            }
            catch (...) {}

            Probe p = RunProbe();
            json out;
            out["ok"] = p.ok;
            out["source"] = p.source;
            out["db_count"] = p.dbCount;
            out["detail"] = p.detail;
            out["wxid"] = p.wxid;
            out["data_dir"] = p.dataDir;
            out["g_IsLogin_before"] = (uint64_t)g_IsLogin;

            if (p.ok)
            {
                g_IsLogin = 1;
                if (!p.wxid.empty() && SelfInfo.wxid.empty()) SelfInfo.wxid = p.wxid;
            }
            out["g_IsLogin_after"] = (uint64_t)g_IsLogin;
            out["onlinestatus"] = p.ok ? "3" : "1";
            res.set_content(out.dump(2), "application/json");
        });
    }
}
}
