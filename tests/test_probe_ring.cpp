#include "../include/wxcx_probe_ring.h"
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

static void Check(bool condition)
{
    if (!condition) { std::fputs("FAIL: torn, duplicated or unaccounted record\n", stderr); std::abort(); }
}

struct Payload
{
    uint64_t sequence, tag, mirror[48];
};

static Payload Make(uint64_t tag)
{
    Payload p{};
    p.tag = tag;
    for (auto& v : p.mirror) v = tag ^ 0xBAADC0FFEE123456ULL;
    return p;
}

int main()
{
    wxcx::probe::RecordRing<Payload, 4> small;
    for (uint64_t i = 1; i <= 6; ++i) Check(small.TryPush(Make(i)));
    Payload out[4];
    auto batch = small.TryDrain(out, 2);
    Check(!batch.busy && batch.count == 2 && batch.skipped == 2);
    Check(small.Dropped() == 2 && small.Skipped() == 2);
    Check(out[0].tag == 5 && out[1].tag == 6 && out[0].sequence == 5);
    Check(small.TryDrain(out, 4).count == 0);

    wxcx::probe::RecordRing<Payload, 64> ring;
    constexpr uint64_t perProducer = 25000, producers = 4;
    std::atomic<bool> done{false};
    std::atomic<uint64_t> consumed{0};
    auto reader = [&] {
        Payload records[32];
        uint64_t last = 0;
        for (;;)
        {
            const auto b = ring.TryDrain(records, 32);
            for (size_t i = 0; i < b.count; ++i)
            {
                Check(records[i].sequence > last);
                last = records[i].sequence;
                for (auto v : records[i].mirror) Check(v == (records[i].tag ^ 0xBAADC0FFEE123456ULL));
                consumed.fetch_add(1);
            }
            if (done.load() && !b.busy && b.count == 0) break;
            std::this_thread::yield();
        }
    };
    std::thread r1(reader), r2(reader);
    std::vector<std::thread> workers;
    for (uint64_t p = 0; p < producers; ++p)
        workers.emplace_back([&, p] {
            for (uint64_t i = 0; i < perProducer; ++i)
                ring.TryPush(Make((p << 32) | i));
        });
    for (auto& worker : workers) worker.join();
    done = true;
    r1.join(); r2.join();
    Check(consumed.load() + ring.Dropped() + ring.Skipped() == perProducer * producers);
    std::printf("PASS: bounded overflow, explicit truncation, 4 producers/2 readers, 100000 observations accounted\n");
}
