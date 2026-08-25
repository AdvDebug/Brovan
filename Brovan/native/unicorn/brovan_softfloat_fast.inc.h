/* MSVC has no flatten attribute: the hardfloat dispatch keeps its function
   pointers live and the soft path inlines into the hot entry points. Restore
   the shape upstream gets from gcc. */
#ifndef BROVAN_SOFTFLOAT_FAST_INC_H
#define BROVAN_SOFTFLOAT_FAST_INC_H

#ifdef _MSC_VER
#undef QEMU_SOFTFLOAT_ATTR
#define QEMU_SOFTFLOAT_ATTR __declspec(noinline)
#define BROV_SF_INLINE __forceinline
/* fpclassify is a CRT call under MSVC; the integer classifiers inline. */
#undef QEMU_HARDFLOAT_1F64_USE_FP
#undef QEMU_HARDFLOAT_2F64_USE_FP
#undef QEMU_HARDFLOAT_3F64_USE_FP
#define QEMU_HARDFLOAT_1F64_USE_FP 0
#define QEMU_HARDFLOAT_2F64_USE_FP 0
#define QEMU_HARDFLOAT_3F64_USE_FP 0
#else
#define BROV_SF_INLINE inline
#endif

/* Nothing reads these flags back into guest MXCSR; the seed only holds
   can_use_fpu()'s precondition from reset onward. */
static inline void brov_seed_inexact(float_status *s)
{
    s->float_exception_flags |= float_flag_inexact;
}

#endif
