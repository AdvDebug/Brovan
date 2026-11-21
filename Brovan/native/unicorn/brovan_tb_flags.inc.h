/* The bits Brovan adds to the translation block flags. A lookup under other flags finds other blocks.
 *
 * HF_BROV_FPN: MXCSR is not part of the flags upstream, so a block has no way to know whether the host FPU will
 * answer the way the guest asked. The bit says it will: round to nearest, no flush to zero, no denormals are
 * zero. Any other MXCSR keeps the softfloat helpers. ldmxcsr, fxrstor and xrstor end the block so a change
 * reaches the next lookup.
 *
 * HF_BROV_FAR_CHAIN: with paging off, a direct jump may link to a block on another page. The target page then
 * changes only by an unmap, a store to its code or a loss of EXEC, and each of those invalidates its blocks. A
 * write to CR0 ends its block, so a block with the bit never runs with paging on. */
#ifndef BROVAN_TB_FLAGS_INC_H
#define BROVAN_TB_FLAGS_INC_H

#ifdef TARGET_I386
#define HF_BROV_FPN_SHIFT 27
#define HF_BROV_FPN_MASK (1 << HF_BROV_FPN_SHIFT)
#define HF_BROV_FAR_CHAIN_SHIFT 28
#define HF_BROV_FAR_CHAIN_MASK (1 << HF_BROV_FAR_CHAIN_SHIFT)
#endif

/* Also included where every target is built, and other targets use these bits for their own flags. */
static inline bool brov_tb_far_chain(uint32_t flags)
{
#ifdef TARGET_I386
    return (flags & HF_BROV_FAR_CHAIN_MASK) != 0;
#else
    (void)flags;
    return false;
#endif
}

#ifdef TARGET_I386

/* DAZ bit 6, RC bits 14 and 13, FZ bit 15. */
#define BROV_MXCSR_NONDEFAULT 0xe040

static inline bool brov_far_chain_off(void)
{
    static int off = -1;

    if (off < 0) {
        off = getenv("BROVAN_NO_FAR_CHAIN") != NULL;
    }
    return off != 0;
}

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
    if ((env->cr[0] & CR0_PG_MASK) == 0 && !brov_far_chain_off()) {
        f |= HF_BROV_FAR_CHAIN_MASK;
    }
    *flags = f;
}

#endif

#endif
