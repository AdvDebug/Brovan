/* The ordinary rep loop follows the call unchanged, and it finishes whatever the call left. */
#ifndef BROVAN_REP_STRING_INC_H
#define BROVAN_REP_STRING_INC_H

static bool brov_rep_fast_off(void)
{
    static int off = -1;

    if (off < 0) {
        off = getenv("BROVAN_NO_REP_FAST") != NULL;
    }
    return off != 0;
}

/* The helper adds no segment base and steps once per run, so it takes no single step. */
static bool brov_rep_fast_ok(DisasContext *s, bool has_source)
{
    if (brov_rep_fast_off() || !s->jmp_opt) {
        return false;
    }
    if (has_source && s->override >= 0) {
        return false;
    }
    if (CODE64(s)) {
        return s->aflag == MO_64;
    }
    return s->aflag == MO_32 && !s->addseg;
}

static void brov_gen_rep_fast(DisasContext *s, MemOp ot, bool has_source)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i32 shift, wide;

    if (!brov_rep_fast_ok(s, has_source)) {
        return;
    }

    shift = tcg_const_i32(tcg_ctx, ot);
    wide = tcg_const_i32(tcg_ctx, s->aflag == MO_64);
    if (has_source) {
        gen_helper_brov_rep_movs(tcg_ctx, tcg_ctx->cpu_env, shift, wide);
    } else {
        gen_helper_brov_rep_stos(tcg_ctx, tcg_ctx->cpu_env, shift, wide);
    }
    tcg_temp_free_i32(tcg_ctx, wide);
    tcg_temp_free_i32(tcg_ctx, shift);
}

#endif
