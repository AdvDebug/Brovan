/* Ordered operands answer on the host compare; any NaN falls back to the
   renamed soft routine, which keeps invalid raising and NaN conventions in
   one place. Mirrors f64_compare above. NaN detection is by self-compare:
   isunordered() is a CRT call under MSVC. */

#define BROV_CMP_FAST(BITS, NAME, RELOP)                                      \
int float##BITS##_##NAME(float##BITS a, float##BITS b, float_status *status)  \
{                                                                             \
    union_float##BITS ua, ub;                                                 \
    ua.s = a;                                                                 \
    ub.s = b;                                                                 \
    if (!QEMU_NO_HARDFLOAT) {                                                 \
        float##BITS##_input_flush2(&ua.s, &ub.s, status);                     \
        if (likely(ua.h == ua.h && ub.h == ub.h)) {                           \
            return (RELOP);                                                   \
        }                                                                     \
    }                                                                         \
    return brov_soft_float##BITS##_##NAME(ua.s, ub.s, status);                \
}

BROV_CMP_FAST(32, lt, ua.h < ub.h)
BROV_CMP_FAST(32, le, ua.h <= ub.h)
BROV_CMP_FAST(32, eq_quiet, ua.h == ub.h)
BROV_CMP_FAST(32, unordered_quiet, 0)
BROV_CMP_FAST(64, lt, ua.h < ub.h)
BROV_CMP_FAST(64, le, ua.h <= ub.h)
BROV_CMP_FAST(64, eq_quiet, ua.h == ub.h)
BROV_CMP_FAST(64, unordered_quiet, 0)

#undef BROV_CMP_FAST
