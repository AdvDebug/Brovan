/* SSE floating point arithmetic emitted as host instructions rather than as a
 * helper call. The opcodes are declared in brovan_fp_vec_opc.inc.h and emitted
 * by brovan_fp_vec_arm64.inc.c and brovan_fp_vec_i386.inc.c.
 *
 * The packed forms run on TCG_TYPE_V128. The scalar forms run on TCG_TYPE_V64,
 * where the backend emits the host scalar instruction and only lane 0 is
 * defined; a single precision operand is then carried by ld32_vec and st32_vec
 * and a double precision one by the ordinary 8 byte ld_vec and st_vec, so the
 * rest of the destination register keeps its value.
 *
 * The host FPU brings its own rounding mode and its own denormal handling, so
 * this runs only under HF_BROV_FPN_MASK. A NaN operand still propagates by the
 * host rule for which operand wins; tests/fpconform.exe is the gate for that.
 *
 * BROVAN_NO_FPVEC=1 is the kill switch. */
#ifndef BROVAN_FP_VEC_INC_H
#define BROVAN_FP_VEC_INC_H

static bool brov_fp_vec_off(void)
{
    static int off = -1;

    if (off < 0) {
        off = getenv("BROVAN_NO_FPVEC") != NULL;
    }
    return off != 0;
}

static void brov_gen_mxcsr_eob(DisasContext *s)
{
    gen_jmp_im(s, s->pc - s->cs_base);
    gen_eob(s);
}

static void brov_fp_vec_ld(TCGContext *tcg_ctx, TCGv_vec r, TCGType type,
                           unsigned vece, bool narrow, int offset)
{
    if (narrow) {
        vec_gen_3(tcg_ctx, INDEX_op_ld32_vec, type, vece,
                  tcgv_vec_arg(tcg_ctx, r),
                  tcgv_ptr_arg(tcg_ctx, tcg_ctx->cpu_env), offset);
    } else {
        tcg_gen_ld_vec(tcg_ctx, r, tcg_ctx->cpu_env, offset);
    }
}

static void brov_fp_vec_st(TCGContext *tcg_ctx, TCGv_vec r, TCGType type,
                           unsigned vece, bool narrow, int offset)
{
    if (narrow) {
        vec_gen_3(tcg_ctx, INDEX_op_st32_vec, type, vece,
                  tcgv_vec_arg(tcg_ctx, r),
                  tcgv_ptr_arg(tcg_ctx, tcg_ctx->cpu_env), offset);
    } else {
        tcg_gen_st_vec(tcg_ctx, r, tcg_ctx->cpu_env, offset);
    }
}

static bool brov_gen_sse_fp(DisasContext *s, int b, int b1,
                            int op1_offset, int op2_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGOpcode opc;
    TCGType type;
    unsigned vece;
    bool narrow;
    TCGv_vec d, t;

    if (!(s->flags & HF_BROV_FPN_MASK) || brov_fp_vec_off()) {
        return false;
    }

    switch (b) {
    case 0x51: opc = INDEX_op_fsqrt_vec; break;
    case 0x58: opc = INDEX_op_fadd_vec; break;
    case 0x59: opc = INDEX_op_fmul_vec; break;
    case 0x5c: opc = INDEX_op_fsub_vec; break;
    case 0x5e: opc = INDEX_op_fdiv_vec; break;
    default: return false;
    }

    type = b1 >= 2 ? TCG_TYPE_V64 : TCG_TYPE_V128;
    vece = (b1 & 1) ? MO_64 : MO_32;
    narrow = b1 == 2;

    if (tcg_can_emit_vec_op(tcg_ctx, opc, type, vece) <= 0) {
        return false;
    }
    if (narrow &&
        tcg_can_emit_vec_op(tcg_ctx, INDEX_op_st32_vec, type, vece) <= 0) {
        return false;
    }

    d = tcg_temp_new_vec(tcg_ctx, type);
    if (opc == INDEX_op_fsqrt_vec) {
        brov_fp_vec_ld(tcg_ctx, d, type, vece, narrow, op2_offset);
        vec_gen_2(tcg_ctx, opc, type, vece, tcgv_vec_arg(tcg_ctx, d),
                  tcgv_vec_arg(tcg_ctx, d));
    } else {
        t = tcg_temp_new_vec(tcg_ctx, type);
        brov_fp_vec_ld(tcg_ctx, d, type, vece, narrow, op1_offset);
        brov_fp_vec_ld(tcg_ctx, t, type, vece, narrow, op2_offset);
        vec_gen_3(tcg_ctx, opc, type, vece, tcgv_vec_arg(tcg_ctx, d),
                  tcgv_vec_arg(tcg_ctx, d), tcgv_vec_arg(tcg_ctx, t));
        tcg_temp_free_vec(tcg_ctx, t);
    }

    brov_fp_vec_st(tcg_ctx, d, type, vece, narrow, op1_offset);
    tcg_temp_free_vec(tcg_ctx, d);
    return true;
}

#endif
