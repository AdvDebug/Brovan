/* Emitters for the opcodes in brovan_fp_vec_opc.inc.h.
 *
 * Advanced SIMD three-same puts the bit that separates FADD from FSUB at 23,
 * inside the field tcg_out_insn_3616 shifts its size argument into, so that bit
 * is baked into the word and only the 64 bit select is passed as the size. The
 * scalar words hold ftype in the same two bits, where 23 is always clear, so the
 * same call works for both. */
#ifndef BROVAN_FP_VEC_ARM64_INC_C
#define BROVAN_FP_VEC_ARM64_INC_C

enum {
    BROV_FADD_V  = 0x0e20d400,
    BROV_FSUB_V  = 0x0ea0d400,
    BROV_FMUL_V  = 0x2e20dc00,
    BROV_FDIV_V  = 0x2e20fc00,
    BROV_FSQRT_V = 0x2ea1f800,
    BROV_FADD_S  = 0x1e202800,
    BROV_FSUB_S  = 0x1e203800,
    BROV_FMUL_S  = 0x1e200800,
    BROV_FDIV_S  = 0x1e201800,
    BROV_FSQRT_S = 0x1e21c000,
    BROV_FCMGT_V = 0x2e20e400,
    BROV_FCMGT_S = 0x7e20e400,
};

static const TCGTargetOpDef brov_w_w_w = { .args_ct_str = { "w", "w", "w" } };
static const TCGTargetOpDef brov_w_w = { .args_ct_str = { "w", "w" } };
static const TCGTargetOpDef brov_w_r = { .args_ct_str = { "w", "r" } };

static const TCGTargetOpDef *brov_fp_vec_op_def(TCGOpcode op)
{
    switch (op) {
    case INDEX_op_fadd_vec:
    case INDEX_op_fsub_vec:
    case INDEX_op_fmul_vec:
    case INDEX_op_fdiv_vec:
    case INDEX_op_fmax_vec:
    case INDEX_op_fmin_vec:
        return &brov_w_w_w;
    case INDEX_op_fsqrt_vec:
        return &brov_w_w;
    case INDEX_op_ld32_vec:
    case INDEX_op_st32_vec:
        return &brov_w_r;
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
    case INDEX_op_fmax_vec:
    case INDEX_op_fmin_vec:
    case INDEX_op_fsqrt_vec:
    case INDEX_op_ld32_vec:
    case INDEX_op_st32_vec:
        break;
    default:
        return -1;
    }
    if (type != TCG_TYPE_V64 && type != TCG_TYPE_V128) {
        return 0;
    }
    return (vece == MO_32 || vece == MO_64) ? 1 : 0;
}

static bool brov_fp_vec_out(TCGContext *s, TCGOpcode opc, unsigned vecl,
                            unsigned vece, const TCGArg *args)
{
    bool scalar = vecl == 0;
    unsigned size = vece == MO_64;
    int insn;

    switch (opc) {
    case INDEX_op_ld32_vec:
        tcg_out_ld(s, TCG_TYPE_I32, args[0], args[1], args[2]);
        return true;
    case INDEX_op_st32_vec:
        tcg_out_st(s, TCG_TYPE_I32, args[0], args[1], args[2]);
        return true;
    case INDEX_op_fsqrt_vec:
        insn = scalar ? BROV_FSQRT_S : BROV_FSQRT_V;
        tcg_out_insn_3617(s, (AArch64Insn)insn, !scalar, size,
                          args[0], args[1]);
        return true;
    case INDEX_op_fmax_vec:
    case INDEX_op_fmin_vec: {
        /* x86 max and min give the second operand when the pair is unordered
         * or equal, so this is a compare and a select. BSL takes its mask in
         * the destination, so it runs in the scratch and the result is moved
         * out, because the operands may alias the destination. Vector FCMGT
         * with Q clear and size set is the undefined 1D form, so the scalar
         * cases take the scalar encoding. */
        bool max = opc == INDEX_op_fmax_vec;
        TCGReg lhs = max ? args[1] : args[2];
        TCGReg rhs = max ? args[2] : args[1];

        tcg_out_insn_3616(s, (AArch64Insn)(scalar ? BROV_FCMGT_S : BROV_FCMGT_V),
                          !scalar, size, TCG_VEC_TMP, lhs, rhs);
        tcg_out_insn(s, 3616, BSL, !scalar, 0, TCG_VEC_TMP, args[1], args[2]);
        tcg_out_mov(s, scalar ? TCG_TYPE_V64 : TCG_TYPE_V128,
                    args[0], TCG_VEC_TMP);
        return true;
    }
    case INDEX_op_fadd_vec: insn = scalar ? BROV_FADD_S : BROV_FADD_V; break;
    case INDEX_op_fsub_vec: insn = scalar ? BROV_FSUB_S : BROV_FSUB_V; break;
    case INDEX_op_fmul_vec: insn = scalar ? BROV_FMUL_S : BROV_FMUL_V; break;
    case INDEX_op_fdiv_vec: insn = scalar ? BROV_FDIV_S : BROV_FDIV_V; break;
    default:
        return false;
    }
    tcg_out_insn_3616(s, (AArch64Insn)insn, !scalar, size,
                      args[0], args[1], args[2]);
    return true;
}

#endif
