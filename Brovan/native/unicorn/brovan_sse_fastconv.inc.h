/* Conversions have no hardfloat layer. In-range finite values convert on the
   host; anything that could raise invalid, flush, or need a rounding mode
   other than the host's falls back to softfloat. */
#ifndef BROVAN_SSE_FASTCONV_INC_H
#define BROVAN_SSE_FASTCONV_INC_H

#include <float.h>
#include <math.h>

static inline float64 brov_i32_to_f64(int32_t v)
{
    union { float64 s; double h; } u;
    u.h = v;
    return u.s;
}

static inline float32 brov_i32_to_f32(int32_t v, float_status *s)
{
    union { float32 f; float h; } u;
    double dv;
    if (s->float_rounding_mode != float_round_nearest_even) {
        return int32_to_float32(v, s);
    }
    dv = v;
    u.h = (float)dv;
    if ((double)u.h != dv) {
        s->float_exception_flags |= float_flag_inexact;
    }
    return u.f;
}

#define BROV_WRAP_RTZ(RETTYPE, FN, FLOATTYPE, HOSTTYPE, MIN_C, LO, HI, INDEFVALUE) \
    static inline RETTYPE x86_##FN(FLOATTYPE a, float_status *s)        \
    {                                                                   \
        union { FLOATTYPE f; HOSTTYPE h; } u;                           \
        int oldflags, newflags;                                         \
        RETTYPE r;                                                      \
        u.f = a;                                                        \
        if ((u.h == 0 || u.h >= MIN_C || u.h <= -(MIN_C)) &&            \
            u.h >= (LO) && u.h < (HI)) {                                \
            r = (RETTYPE)u.h;                                           \
            if ((double)r != (double)u.h) {                             \
                s->float_exception_flags |= float_flag_inexact;         \
            }                                                           \
            return r;                                                   \
        }                                                               \
        oldflags = get_float_exception_flags(s);                        \
        set_float_exception_flags(0, s);                                \
        r = FN(a, s);                                                   \
        newflags = get_float_exception_flags(s);                        \
        if (newflags & float_flag_invalid) {                            \
            r = INDEFVALUE;                                             \
        }                                                               \
        set_float_exception_flags(newflags | oldflags, s);              \
        return r;                                                       \
    }

BROV_WRAP_RTZ(int32_t, float32_to_int32_round_to_zero, float32, float,
              FLT_MIN, -2147483648.0f, 2147483648.0f, INT32_MIN)
BROV_WRAP_RTZ(int32_t, float64_to_int32_round_to_zero, float64, double,
              DBL_MIN, -2147483648.0, 2147483648.0, INT32_MIN)
BROV_WRAP_RTZ(int64_t, float32_to_int64_round_to_zero, float32, float,
              FLT_MIN, -9223372036854775808.0f, 9223372036854775808.0f, INT64_MIN)
BROV_WRAP_RTZ(int64_t, float64_to_int64_round_to_zero, float64, double,
              DBL_MIN, -9223372036854775808.0, 9223372036854775808.0, INT64_MIN)

#undef BROV_WRAP_RTZ

#endif
