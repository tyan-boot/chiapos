#include "iostream"

#if defined(_WIN32)
#include <intrin.h>
#elif defined(__x86_64__)

#include <cpuid.h>

#endif


#ifndef _WIN32
typedef __uint128_t uint128_t;

// Allows printing of uint128_t
std::ostream &operator<<(std::ostream &strm, uint128_t const &v) {
    strm << "uint128(" << (uint64_t) (v >> 64) << "," << (uint64_t) (v & (((uint128_t) 1 << 64) - 1))
         << ")";
    return strm;
}

#endif

namespace Util {

#if defined(_WIN32) || defined(__x86_64__)

    void CpuID(uint32_t leaf, uint32_t *regs) {
#if defined(_WIN32)
        __cpuid((int *)regs, (int)leaf);
#else
        __get_cpuid(leaf, &regs[0], &regs[1], &regs[2], &regs[3]);
#endif /* defined(_WIN32) */
    }

    bool HavePopcnt(void) {
        // EAX, EBX, ECX, EDX
        uint32_t regs[4] = {0};

        CpuID(1, regs);
        // Bit 23 of ECX indicates POPCNT instruction support
        return (regs[2] >> 23) & 1;
    }

#endif /* defined(_WIN32) || defined(__x86_64__) */

}