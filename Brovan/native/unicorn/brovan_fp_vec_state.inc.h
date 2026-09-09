/* MXCSR is not part of the translation block flags upstream, so a block has no
 * way to know whether the host FPU will answer the way the guest asked. This
 * carries the one bit that says it will: round to nearest, no flush to zero, no
 * denormals are zero. Any other MXCSR keeps the softfloat helpers.
 *
 * ldmxcsr, fxrstor and xrstor end the block so a change reaches the next
 * lookup. */
#ifndef BROVAN_FP_VEC_STATE_INC_H
#define BROVAN_FP_VEC_STATE_INC_H

#define HF_BROV_FPN_SHIFT   27
#define HF_BROV_FPN_MASK    (1 << HF_BROV_FPN_SHIFT)

/* DAZ bit 6, RC bits 14 and 13, FZ bit 15. */
#define BROV_MXCSR_NONDEFAULT 0xe040

static inline void brov_tb_cpu_state(CPUX86State *env, target_ulong *pc,
                                     target_ulong *cs_base, uint32_t *flags)
{
    uint32_t f;

    *cs_base = env->segs[R_CS].base;
    *pc = *cs_base + env->eip;
    f = env->hflags |
        (env->eflags & (IOPL_MASK | TF_MASK | RF_MASK | VM_MASK | AC_MASK));
    if ((env->mxcsr & BROV_MXCSR_NONDEFAULT) == 0) {
        f |= HF_BROV_FPN_MASK;
    }
    *flags = f;
}

#endif
