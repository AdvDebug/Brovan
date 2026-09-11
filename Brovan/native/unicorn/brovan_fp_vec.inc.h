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
    case 0x5d: opc = INDEX_op_fmin_vec; break;
    case 0x5e: opc = INDEX_op_fdiv_vec; break;
    case 0x5f: opc = INDEX_op_fmax_vec; break;
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

/* Integer SSE operations that have one host vector instruction with the same
 * semantics. Bit exact, so no MXCSR condition and no NaN question.
 *
 * Claimed by helper pointer and not by opcode byte, because the generic call
 * site in gen_sse is reached from two tables: 0xdb and 0xdf are pand and pandn
 * in sse_op_table1 and AESIMC and AESDECLAST in sse_op_table6.
 *
 * op1_offset is the destination at every call site that reaches a claimed
 * helper.
 *
 * TCG_TARGET_HAS_brov_widemove marks a host where a 128 bit slot access
 * forwards as well as a 64 bit one. The quad sized helpers are claimed only
 * there, and brov_gen_movo follows it so the widths in a block agree.
 *
 * BROVAN_NO_SSEVEC=1 is the kill switch. */
#ifndef TCG_TARGET_HAS_brov_widemove
#define TCG_TARGET_HAS_brov_widemove 0
#endif

enum {
    BROV_VEC_NONE = 0,
    BROV_VEC_AND,
    BROV_VEC_ANDC,
    BROV_VEC_OR,
    BROV_VEC_XOR,
    BROV_VEC_ADD,
    BROV_VEC_SUB,
    BROV_VEC_MUL,
    BROV_VEC_SSADD,
    BROV_VEC_USADD,
    BROV_VEC_SSSUB,
    BROV_VEC_USSUB,
    BROV_VEC_SMIN,
    BROV_VEC_SMAX,
    BROV_VEC_UMIN,
    BROV_VEC_UMAX,
    BROV_VEC_CMPEQ,
    BROV_VEC_CMPGT,
};

static bool brov_sse_vec_off(void)
{
    static int off = -1;

    if (off < 0) {
        off = getenv("BROVAN_NO_SSEVEC") != NULL;
    }
    return off != 0;
}

static int brov_sse_vec_kind(SSEFunc_0_epp fn, unsigned *vece)
{
#define BROV_VEC_CLAIM(helper, kind, e)                                 \
    if (fn == (SSEFunc_0_epp)gen_helper_##helper##_xmm) {               \
        *vece = (e);                                                    \
        return (kind);                                                  \
    }
#if TCG_TARGET_HAS_brov_widemove
    BROV_VEC_CLAIM(pand,    BROV_VEC_AND,   MO_64)
    BROV_VEC_CLAIM(pandn,   BROV_VEC_ANDC,  MO_64)
    BROV_VEC_CLAIM(por,     BROV_VEC_OR,    MO_64)
    BROV_VEC_CLAIM(pxor,    BROV_VEC_XOR,   MO_64)
    BROV_VEC_CLAIM(paddq,   BROV_VEC_ADD,   MO_64)
    BROV_VEC_CLAIM(psubq,   BROV_VEC_SUB,   MO_64)
#endif
    BROV_VEC_CLAIM(paddb,   BROV_VEC_ADD,   MO_8)
    BROV_VEC_CLAIM(paddw,   BROV_VEC_ADD,   MO_16)
    BROV_VEC_CLAIM(paddl,   BROV_VEC_ADD,   MO_32)
    BROV_VEC_CLAIM(psubb,   BROV_VEC_SUB,   MO_8)
    BROV_VEC_CLAIM(psubw,   BROV_VEC_SUB,   MO_16)
    BROV_VEC_CLAIM(psubl,   BROV_VEC_SUB,   MO_32)
    BROV_VEC_CLAIM(pmullw,  BROV_VEC_MUL,   MO_16)

    BROV_VEC_CLAIM(paddsb,  BROV_VEC_SSADD, MO_8)
    BROV_VEC_CLAIM(paddsw,  BROV_VEC_SSADD, MO_16)
    BROV_VEC_CLAIM(paddusb, BROV_VEC_USADD, MO_8)
    BROV_VEC_CLAIM(paddusw, BROV_VEC_USADD, MO_16)
    BROV_VEC_CLAIM(psubsb,  BROV_VEC_SSSUB, MO_8)
    BROV_VEC_CLAIM(psubsw,  BROV_VEC_SSSUB, MO_16)
    BROV_VEC_CLAIM(psubusb, BROV_VEC_USSUB, MO_8)
    BROV_VEC_CLAIM(psubusw, BROV_VEC_USSUB, MO_16)

    BROV_VEC_CLAIM(pminub,  BROV_VEC_UMIN,  MO_8)
    BROV_VEC_CLAIM(pmaxub,  BROV_VEC_UMAX,  MO_8)
    BROV_VEC_CLAIM(pminsw,  BROV_VEC_SMIN,  MO_16)
    BROV_VEC_CLAIM(pmaxsw,  BROV_VEC_SMAX,  MO_16)

    BROV_VEC_CLAIM(pcmpeqb, BROV_VEC_CMPEQ, MO_8)
    BROV_VEC_CLAIM(pcmpeqw, BROV_VEC_CMPEQ, MO_16)
    BROV_VEC_CLAIM(pcmpeql, BROV_VEC_CMPEQ, MO_32)
    BROV_VEC_CLAIM(pcmpgtb, BROV_VEC_CMPGT, MO_8)
    BROV_VEC_CLAIM(pcmpgtw, BROV_VEC_CMPGT, MO_16)
    BROV_VEC_CLAIM(pcmpgtl, BROV_VEC_CMPGT, MO_32)
#undef BROV_VEC_CLAIM
    return BROV_VEC_NONE;
}

static TCGOpcode brov_sse_vec_opc(int kind)
{
    switch (kind) {
    case BROV_VEC_AND:   return INDEX_op_and_vec;
    case BROV_VEC_ANDC:  return INDEX_op_andc_vec;
    case BROV_VEC_OR:    return INDEX_op_or_vec;
    case BROV_VEC_XOR:   return INDEX_op_xor_vec;
    case BROV_VEC_ADD:   return INDEX_op_add_vec;
    case BROV_VEC_SUB:   return INDEX_op_sub_vec;
    case BROV_VEC_MUL:   return INDEX_op_mul_vec;
    case BROV_VEC_SSADD: return INDEX_op_ssadd_vec;
    case BROV_VEC_USADD: return INDEX_op_usadd_vec;
    case BROV_VEC_SSSUB: return INDEX_op_sssub_vec;
    case BROV_VEC_USSUB: return INDEX_op_ussub_vec;
    case BROV_VEC_SMIN:  return INDEX_op_smin_vec;
    case BROV_VEC_SMAX:  return INDEX_op_smax_vec;
    case BROV_VEC_UMIN:  return INDEX_op_umin_vec;
    case BROV_VEC_UMAX:  return INDEX_op_umax_vec;
    default:             return INDEX_op_cmp_vec;
    }
}

/* Packed shift by immediate. x86 gives zero for a count at or above the
 * element width, or all sign bits for an arithmetic shift. */
static bool brov_gen_sse_shifti(DisasContext *s, int b, int b1, int is_xmm,
                                int val, int modrm)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int group = ((b - 1) & 3);
    int op = (modrm >> 3) & 7;
    unsigned vece = MO_16 + group;
    int bits = 8 << vece;
    TCGOpcode opc;
    TCGv_vec d;
    int dst;

    if (!is_xmm || !TCG_TARGET_HAS_v128 || brov_sse_vec_off()) {
        return false;
    }
    if (!sse_op_table2[group * 8 + op][b1]) {
        return false;
    }

    switch (op) {
    case 2: opc = INDEX_op_shri_vec; break;
    case 4: opc = INDEX_op_sari_vec; break;
    case 6: opc = INDEX_op_shli_vec; break;
    default: return false;
    }
    if (tcg_can_emit_vec_op(tcg_ctx, opc, TCG_TYPE_V128, vece) == 0) {
        return false;
    }

    if (val == 0) {
        return true;
    }

    dst = offsetof(CPUX86State, xmm_regs[0]) +
          ((modrm & 7) | REX_B(s)) * (int)sizeof(ZMMReg);
    d = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);

    if (val >= bits && opc != INDEX_op_sari_vec) {
        tcg_gen_dupi_vec(tcg_ctx, MO_64, d, 0);
    } else {
        int amount = val >= bits ? bits - 1 : val;

        tcg_gen_ld_vec(tcg_ctx, d, tcg_ctx->cpu_env, dst);
        if (opc == INDEX_op_shri_vec) {
            tcg_gen_shri_vec(tcg_ctx, vece, d, d, amount);
        } else if (opc == INDEX_op_sari_vec) {
            tcg_gen_sari_vec(tcg_ctx, vece, d, d, amount);
        } else {
            tcg_gen_shli_vec(tcg_ctx, vece, d, d, amount);
        }
    }

    tcg_gen_st_vec(tcg_ctx, d, tcg_ctx->cpu_env, dst);
    tcg_temp_free_vec(tcg_ctx, d);
    return true;
}

static bool brov_gen_movo(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_vec t;

    if (!TCG_TARGET_HAS_brov_widemove || !TCG_TARGET_HAS_v128 ||
        brov_sse_vec_off()) {
        return false;
    }

    t = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);
    tcg_gen_ld_vec(tcg_ctx, t, tcg_ctx->cpu_env, s_offset);
    tcg_gen_st_vec(tcg_ctx, t, tcg_ctx->cpu_env, d_offset);
    tcg_temp_free_vec(tcg_ctx, t);
    return true;
}

static bool brov_gen_sse_vec(DisasContext *s, SSEFunc_0_epp fn,
                             int op1_offset, int op2_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vece = MO_64;
    TCGv_vec d, t;
    int kind;

    if (!TCG_TARGET_HAS_v128 || brov_sse_vec_off()) {
        return false;
    }

    kind = brov_sse_vec_kind(fn, &vece);
    if (kind == BROV_VEC_NONE) {
        return false;
    }
    if (tcg_can_emit_vec_op(tcg_ctx, brov_sse_vec_opc(kind),
                            TCG_TYPE_V128, vece) == 0) {
        return false;
    }

    d = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);

    if (op1_offset == op2_offset &&
        (kind == BROV_VEC_SUB || kind == BROV_VEC_CMPGT ||
         kind == BROV_VEC_XOR || kind == BROV_VEC_ANDC)) {
        tcg_gen_dupi_vec(tcg_ctx, MO_64, d, 0);
        tcg_gen_st_vec(tcg_ctx, d, tcg_ctx->cpu_env, op1_offset);
        tcg_temp_free_vec(tcg_ctx, d);
        return true;
    }

    t = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);

    if (kind == BROV_VEC_ANDC) {
        /* x86 inverts the destination, the opposite of the TCG operand order */
        tcg_gen_ld_vec(tcg_ctx, d, tcg_ctx->cpu_env, op2_offset);
        tcg_gen_ld_vec(tcg_ctx, t, tcg_ctx->cpu_env, op1_offset);
        tcg_gen_andc_vec(tcg_ctx, vece, d, d, t);
        tcg_gen_st_vec(tcg_ctx, d, tcg_ctx->cpu_env, op1_offset);
        tcg_temp_free_vec(tcg_ctx, t);
        tcg_temp_free_vec(tcg_ctx, d);
        return true;
    }

    tcg_gen_ld_vec(tcg_ctx, d, tcg_ctx->cpu_env, op1_offset);
    tcg_gen_ld_vec(tcg_ctx, t, tcg_ctx->cpu_env, op2_offset);

    switch (kind) {
    case BROV_VEC_AND:   tcg_gen_and_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_OR:    tcg_gen_or_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_XOR:   tcg_gen_xor_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_ADD:   tcg_gen_add_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_SUB:   tcg_gen_sub_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_MUL:   tcg_gen_mul_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_SSADD: tcg_gen_ssadd_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_USADD: tcg_gen_usadd_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_SSSUB: tcg_gen_sssub_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_USSUB: tcg_gen_ussub_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_SMIN:  tcg_gen_smin_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_SMAX:  tcg_gen_smax_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_UMIN:  tcg_gen_umin_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_UMAX:  tcg_gen_umax_vec(tcg_ctx, vece, d, d, t); break;
    case BROV_VEC_CMPEQ:
        tcg_gen_cmp_vec(tcg_ctx, TCG_COND_EQ, vece, d, d, t);
        break;
    default:
        tcg_gen_cmp_vec(tcg_ctx, TCG_COND_GT, vece, d, d, t);
        break;
    }

    tcg_gen_st_vec(tcg_ctx, d, tcg_ctx->cpu_env, op1_offset);
    tcg_temp_free_vec(tcg_ctx, t);
    tcg_temp_free_vec(tcg_ctx, d);
    return true;
}

#endif
