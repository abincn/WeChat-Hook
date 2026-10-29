#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace wxcx { namespace probe {

// Bounded, non-waiting publication. A busy producer drops its observation;
// readers never see a record before the complete POD copy has been published.
// T must have a uint64_t sequence field. No allocation or OS calls occur here.
template<class T, size_t Capacity>
class RecordRing
{
    static_assert(Capacity > 0, "nonempty ring required");
    static_assert(std::is_trivially_copyable<T>::value, "POD records required");
    std::atomic_flag access_ = ATOMIC_FLAG_INIT;
    T records_[Capacity]{};
    uint64_t head_ = 0;
    uint64_t tail_ = 0;
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> skipped_{0};

public:
    struct Batch
    {
        size_t count = 0;
        bool busy = false;
        uint64_t skipped = 0;
        uint64_t published = 0;
    };

    bool TryPush(const T& value)
    {
        if (access_.test_and_set(std::memory_order_acquire))
        {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        if (head_ - tail_ == Capacity)
        {
            ++tail_;
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
        T& dest = records_[head_ % Capacity];
        dest = value;
        dest.sequence = head_ + 1;
        ++head_;
        access_.clear(std::memory_order_release);
        return true;
    }

    Batch TryDrain(T* output, size_t capacity)
    {
        Batch result;
        if (access_.test_and_set(std::memory_order_acquire))
        {
            result.busy = true;
            return result;
        }
        uint64_t start = tail_;
        const uint64_t available = head_ - tail_;
        if (available > capacity)
        {
            result.skipped = available - capacity;
            start += result.skipped;
            skipped_.fetch_add(result.skipped, std::memory_order_relaxed);
        }
        result.published = head_;
        for (uint64_t i = start; i < head_; ++i)
            output[result.count++] = records_[i % Capacity];
        tail_ = head_;
        access_.clear(std::memory_order_release);
        return result;
    }

    uint64_t Dropped() const { return dropped_.load(std::memory_order_relaxed); }
    uint64_t Skipped() const { return skipped_.load(std::memory_order_relaxed); }
};

}}
