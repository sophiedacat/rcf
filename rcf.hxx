#pragma once

#ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace rcf {

namespace detail {

constexpr uint64_t prime64_1 = 0x9E3779B185EBCA87ULL;
constexpr uint64_t prime64_2 = 0xC2B2AE3D27D4EB4FULL;
constexpr uint64_t prime64_3 = 0x165667B19E3779F9ULL;
constexpr uint64_t prime64_4 = 0x85EBCA77C2B2AE63ULL;
constexpr uint64_t prime64_5 = 0x27D4EB2F165667C5ULL;

inline uint64_t rotl64(uint64_t x, int r) { return (x << r) | (x >> (64 - r)); }

inline uint64_t read64(const void* p) {
    uint64_t v; __builtin_memcpy(&v, p, 8); return v;
}
inline uint32_t read32(const void* p) {
    uint32_t v; __builtin_memcpy(&v, p, 4); return v;
}

inline uint64_t round64(uint64_t acc, uint64_t input) {
    acc += input * prime64_2;
    acc  = rotl64(acc, 31);
    acc *= prime64_1;
    return acc;
}

inline uint64_t merge_round(uint64_t acc, uint64_t val) {
    val  = round64(0, val);
    acc ^= val;
    acc  = acc * prime64_1 + prime64_4;
    return acc;
}

inline uint64_t xxh64(const void* data, size_t len, uint64_t seed) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    const uint8_t* const end = p + len;
    uint64_t h;

    if (len >= 32) {
        const uint8_t* const limit = end - 32;
        uint64_t v1 = seed + prime64_1 + prime64_2;
        uint64_t v2 = seed + prime64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - prime64_1;

        do {
            v1 = round64(v1, read64(p)); p += 8;
            v2 = round64(v2, read64(p)); p += 8;
            v3 = round64(v3, read64(p)); p += 8;
            v4 = round64(v4, read64(p)); p += 8;
        } while (p <= limit);

        h = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
        h = merge_round(h, v1);
        h = merge_round(h, v2);
        h = merge_round(h, v3);
        h = merge_round(h, v4);
    } else {
        h = seed + prime64_5;
    }

    h += static_cast<uint64_t>(len);

    while (p + 8 <= end) {
        h ^= round64(0, read64(p));
        h  = rotl64(h, 27) * prime64_1 + prime64_4;
        p += 8;
    }
    if (p + 4 <= end) {
        h ^= static_cast<uint64_t>(read32(p)) * prime64_1;
        h  = rotl64(h, 23) * prime64_2 + prime64_3;
        p += 4;
    }
    while (p < end) {
        h ^= (*p) * prime64_5;
        h  = rotl64(h, 11) * prime64_1;
        ++p;
    }

    h ^= h >> 33; h *= prime64_2;
    h ^= h >> 29; h *= prime64_3;
    h ^= h >> 32;
    return h;
}

struct range {
    const uint8_t* base;
    size_t         size;
};

constexpr size_t max_ranges = 64;

struct baseline {
    SRWLOCK  lock;
    range    ranges[max_ranges];
    size_t   count;
    uint64_t digest;
    uint64_t seed;
    bool     valid;
};

inline baseline& state() {
    static baseline s = { SRWLOCK_INIT, {}, 0, 0, 0, false };
    return s;
}

inline bool is_in_routine(const uint8_t* base, size_t size) {
    const uint8_t* self_lo = reinterpret_cast<const uint8_t*>(&detail::xxh64);
    const uint8_t* self_hi = self_lo + 0x400;
    return !(base + size <= self_lo || base >= self_hi);
}

inline size_t collect_text_ranges(range* out, size_t cap) {
    HMODULE hmod = GetModuleHandleW(nullptr);
    if (!hmod) return 0;

    auto* base = reinterpret_cast<const uint8_t*>(hmod);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto* sect = IMAGE_FIRST_SECTION(nt);
    size_t n = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && n < cap; ++i) {
        const auto& s = sect[i];
        const DWORD chars = s.Characteristics;
        if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (  chars & IMAGE_SCN_MEM_WRITE)   continue;

        const uint8_t* sbase = base + s.VirtualAddress;
        size_t ssize = s.Misc.VirtualSize;
        if (ssize == 0) continue;

        const uint8_t* p   = sbase;
        const uint8_t* end = sbase + ssize;
        while (p < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
            if (mbi.State != MEM_COMMIT) { p = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize; continue; }
            if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                p = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                continue;
            }
            const uint8_t* rbase = static_cast<const uint8_t*>(mbi.BaseAddress);
            const uint8_t* rend  = rbase + mbi.RegionSize;
            if (rbase < p)      rbase = p;
            if (rend  > end)    rend  = end;
            if (rend <= rbase)  break;

            if (is_in_routine(rbase, static_cast<size_t>(rend - rbase))) {
                p = rend;
                continue;
            }

            out[n++] = { rbase, static_cast<size_t>(rend - rbase) };
            p = rend;
            if (n == cap) return n;
        }
    }
    return n;
}

}

inline bool attest_init(uint64_t seed = 0xDEADBEEFCAFEBABEULL) {
    auto& s = detail::state();
    AcquireSRWLockExclusive(&s.lock);
    s.count = detail::collect_text_ranges(s.ranges, detail::max_ranges);
    s.seed  = seed;
    s.valid = false;

    if (s.count == 0) { ReleaseSRWLockExclusive(&s.lock); return false; }

    uint64_t h = seed;
    for (size_t i = 0; i < s.count; ++i) {
        h = detail::xxh64(s.ranges[i].base, s.ranges[i].size, h);
    }
    s.digest = h;
    s.valid  = true;

    ReleaseSRWLockExclusive(&s.lock);
    return true;
}

inline uint64_t attest_verify(bool* ok) {
    auto& s = detail::state();
    if (!s.valid) { if (ok) *ok = false; return 0; }

    uint64_t h = s.seed;
    for (size_t i = 0; i < s.count; ++i) {
        h = detail::xxh64(s.ranges[i].base, s.ranges[i].size, h);
    }
    if (ok) *ok = (h == s.digest);
    return h;
}

inline uint64_t attest_verify_self(bool* ok) {
    auto& s = detail::state();
    if (!s.valid) { if (ok) *ok = false; return 0; }

    const uint8_t* lo = reinterpret_cast<const uint8_t*>(&detail::xxh64);
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    const uintptr_t page = si.dwPageSize;
    const uint8_t* pbase = reinterpret_cast<const uint8_t*>(
        reinterpret_cast<uintptr_t>(lo) & ~(page - 1));

    uint64_t h = detail::xxh64(pbase, page, s.seed ^ 0xA5A5A5A5A5A5A5A5ULL);
    if (ok) *ok = (h != 0);
    return h;
}

struct attestation_blob {
    uint32_t version;
    uint64_t seed;
    uint64_t code_digest;
    uint64_t self_digest;
};

inline bool attest_blob(attestation_blob* out) {
    auto& s = detail::state();
    if (!s.valid || !out) return false;
    bool ok = false;
    out->version     = 1;
    out->seed        = s.seed;
    out->code_digest = attest_verify(&ok);
    if (!ok) return false;
    out->self_digest = attest_verify_self(nullptr);
    return true;
}

}
