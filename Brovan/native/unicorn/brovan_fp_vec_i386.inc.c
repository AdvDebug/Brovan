/* Emitters for the opcodes in brovan_fp_vec_opc.inc.h.
 *
 * The packed and scalar forms differ only in the mandatory prefix, so one table
 * per operation covers ps, pd, ss and sd. VSQRTPS and VSQRTPD take no vvvv;
 * VSQRTSS and VSQRTSD take one and merge from it, which does not matter because
 * only lane 0 is read back. */
#ifndef BROVAN_FP_VEC_I386_INC_C
#define BROVAN_FP_VEC_I386_INC_C

#define BROV_FP_OPC(B) \
    { (B) | P_EXT, (B) | P_EXT | P_DATA16, \
      (B) | P_EXT | P_SIMDF3, (B) | P_EXT | P_SIMDF2 }

/* VZEROUPPER. Generated code is VEX encoded and the helpers are not, so every
 * crossing costs an AVX to SSE transition unless the clean state is restored
 * first. The transition is larger than the helper call it surrounds. */
static void brov_fp_vec_pre_call(TCGContext *s)
{
    if (have_avx1) {
        tcg_out8(s, 0xc5);
        tcg_out8(s, 0xf8);
        tcg_out8(s, 0x77);
    }
}

static const TCGTargetOpDef brov_x_x_x = { .args_ct_str = { "x", "x", "x" } };
static const TCGTargetOpDef brov_x_x = { .args_ct_str = { "x", "x" } };
static const TCGTargetOpDef brov_x_r = { .args_ct_str = { "x", "r" } };

static const TCGTargetOpDef *brov_fp_vec_op_def(TCGOpcode op)
{
    switch (op) {
    case INDEX_op_fadd_vec:
    case INDEX_op_fsub_vec:
    case INDEX_op_fmul_vec:
    case INDEX_op_fdiv_vec:
        return &brov_x_x_x;
    case INDEX_op_fsqrt_vec:
        return &brov_x_x;
    case INDEX_op_ld32_vec:
    case INDEX_op_st32_vec:
        return &brov_x_r;
    default:
        return NULL;
    }
}

/* -1 means the opcode is not one of these, so the caller keeps its own answer. */
static int brov_fp_vec_can_emit(TCGOpcode opc, TCGType type, unsigned vece)
{
    switch (opc) {
    case INDEX_op_fadd_vec:
    case INDEX_op_fsub_vec:
    case INDEX_op_fmul_vec:
    case INDEX_op_fdiv_vec:
    case INDEX_op_fsqrt_vec:
    case INDEX_op_ld32_vec:
    case INDEX_op_st32_vec:
        break;
    default:
        return -1;
    }
    if (!have_avx1) {
        return 0;
    }
    if (type != TCG_TYPE_V64 && type != TCG_TYPE_V128) {
        return 0;
    }
    return (vece == MO_32 || vece == MO_64) ? 1 : 0;
}

static bool brov_fp_vec_out(TCGContext *s, TCGOpcode opc, unsigned vecl,
                            unsigned vece, const TCGArg *args)
{
    static const int add_fp[4] = BROV_FP_OPC(0x58);
    static const int mul_fp[4] = BROV_FP_OPC(0x59);
    static const int sub_fp[4] = BROV_FP_OPC(0x5c);
    static const int div_fp[4] = BROV_FP_OPC(0x5e);
    static const int sqrt_fp[4] = BROV_FP_OPC(0x51);

    int scalar = vecl == 0;
    int idx = scalar * 2 + (vece == MO_64);
    int insn;

    switch (opc) {
    case INDEX_op_ld32_vec:
        tcg_out_ld(s, TCG_TYPE_I32, args[0], args[1], args[2]);
        return true;
    case INDEX_op_st32_vec:
        tcg_out_st(s, TCG_TYPE_I32, args[0], args[1], args[2]);
        return true;
    case INDEX_op_fsqrt_vec:
        insn = sqrt_fp[idx];
        if (scalar) {
            tcg_out_vex_modrm(s, insn, args[0], args[1], args[1]);
        } else {
            tcg_out_vex_modrm(s, insn, args[0], 0, args[1]);
        }
        return true;
    case INDEX_op_fadd_vec: insn = add_fp[idx]; break;
    case INDEX_op_fsub_vec: insn = sub_fp[idx]; break;
    case INDEX_op_fmul_vec: insn = mul_fp[idx]; break;
    case INDEX_op_fdiv_vec: insn = div_fp[idx]; break;
    default:
        return false;
    }
    tcg_out_vex_modrm(s, insn, args[0], args[1], args[2]);
    return true;
}

#endif
