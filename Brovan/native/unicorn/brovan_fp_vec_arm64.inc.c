/* Emitters for the opcodes in brovan_fp_vec_opc.inc.h.
 *
 * Advanced SIMD three-same puts the bit that separates FADD from FSUB at 23,
 * inside the field tcg_out_insn_3616 shifts its size argument into, so that bit
 * is baked into the word and only the 64 bit select is passed as the size. The
 * scalar words hold ftype in the same two bits, where 23 is always clear, so the
 * same call works for both.
 *
 * A scalar instruction clears the lanes above lane 0 of its destination. The
 * scalar form of an op must keep them, so its result goes to the scratch
 * register and INS moves lane 0 into the output, which the constraint makes
 * the register of the first input. */
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
    BROV_FCMGT_V = 0x2ea0e400,
    BROV_FCMGT_S = 0x7ea0e400,

    /* Bit 22 selects double precision in each of these. */
    BROV_SCVTF_W = 0x1e220000, /* bit 31 for an x source */
    BROV_FCVTZS_X = 0x9e380000,
    BROV_FCVTNS_X = 0x9e200000,
    BROV_FCMP = 0x1e202000,

    BROV_ZIP1 = 0x0e003800,
    BROV_ZIP2 = 0x0e007800,
    BROV_UZP1 = 0x0e001800,
    BROV_UZP2 = 0x0e005800,
    BROV_TRN1 = 0x0e002800,
    BROV_TRN2 = 0x0e006800,
    BROV_REV64_4S = 0x4ea00800,
    BROV_EXT_8 = 0x6e004000,
    BROV_DUP_4S = 0x4e040400, /* lane at bit 19 */
    BROV_INS_S = 0x6e040400, /* to at bit 19, from at bit 13 */
    BROV_INS_D = 0x6e080400, /* to at bit 20, from at bit 14 */

    BROV_FCVTL = 0x0e617800,
    BROV_FCVTN = 0x0e616800,
    BROV_FCVT_D_S = 0x1e22c000,
    BROV_FCVT_S_D = 0x1e624000,
    BROV_SCVTF_4S = 0x4e21d800,
    BROV_SCVTF_2D = 0x4e61d800,
    BROV_SXTL_2D = 0x0f20a400,

    /* The shift is the lane size times two minus the count, at bit 16. */
    BROV_USHR = 0x6f000400,
    BROV_USRA = 0x6f001400,
    BROV_UMOV_B = 0x0e013c00, /* lane at bit 17 */
    BROV_UMOV_D = 0x4e083c00, /* lane at bit 20 */

    /* Bit 22 selects 32 bit input lanes, bit 30 the high half of the output. */
    BROV_SQXTN = 0x0e214800,
    BROV_SQXTUN = 0x2e212800,

    BROV_FMOV_S_W = 0x1e270000,
    BROV_FMOV_D_X = 0x9e670000,
    BROV_FMOV_W_S = 0x1e260000,
    BROV_FMOV_X_D = 0x9e660000,

    BROV_SXTW_TMP = 0x93407c1e,
    BROV_MOVZ_TMP_I32_MIN = 0x52b0001e,
    BROV_MOVN_TMP_I64_MAX = 0x92f0001e,
    BROV_MOVZ_TMP_I64_MIN = 0xd2f0001e,
    BROV_CCMP_TMP_VC = 0xfa5e7000,
    BROV_CSEL_W_TMP_EQ = 0x1a9e0000,
    BROV_CSEL_X_EQ = 0x9a800000,

    BROV_CSET_LT = 0x1a9fa7e0,
    BROV_CSET_TMP_VS = 0x1a9f77fe,
    BROV_CSINC_TMP_NE = 0x1a9f17de,
    BROV_ORR_W_TMP_LSL = 0x2a1e0000,
};

static const TCGTargetOpDef brov_w_w_w = { .args_ct_str = { "w", "w", "w" } };
static const TCGTargetOpDef brov_w_0_w = { .args_ct_str = { "w", "0", "w" } };
static const TCGTargetOpDef brov_w_0_r = { .args_ct_str = { "w", "0", "r" } };
static const TCGTargetOpDef brov_w_w = { .args_ct_str = { "w", "w" } };
static const TCGTargetOpDef brov_w_r = { .args_ct_str = { "w", "r" } };
static const TCGTargetOpDef brov_r_w = { .args_ct_str = { "r", "w" } };
static const TCGTargetOpDef brov_r_w_w = { .args_ct_str = { "r", "w", "w" } };

static const TCGTargetOpDef *brov_fp_vec_op_def(TCGOpcode op)
{
    switch (op) {
    case INDEX_op_cvti2f_vec:
        return &brov_w_0_r;
    case INDEX_op_cvtf2i_vec:
    case INDEX_op_movv2i_vec:
    case INDEX_op_movmsk_vec:
        return &brov_r_w;
    case INDEX_op_fcomi_vec:
        return &brov_r_w_w;
    case INDEX_op_fadd_vec:
    case INDEX_op_fsub_vec:
    case INDEX_op_fmul_vec:
    case INDEX_op_fdiv_vec:
    case INDEX_op_fmax_vec:
    case INDEX_op_fmin_vec:
    case INDEX_op_fsqrts_vec:
    case INDEX_op_lane0_vec:
    case INDEX_op_fcvts_vec:
        return &brov_w_0_w;
    case INDEX_op_zipl_vec:
    case INDEX_op_ziph_vec:
    case INDEX_op_shuf_vec:
    case INDEX_op_packss_vec:
    case INDEX_op_packus_vec:
        return &brov_w_w_w;
    case INDEX_op_fsqrt_vec:
    case INDEX_op_fcvt_vec:
    case INDEX_op_fcvti_vec:
        return &brov_w_w;
    case INDEX_op_ld32_vec:
    case INDEX_op_movi2v_vec:
        return &brov_w_r;
    default:
        return NULL;
    }
}

/* -1 means the opcode is not one of these, so the caller keeps its own answer. */
static int brov_fp_vec_can_emit(TCGOpcode opc, TCGType type, unsigned vece)
{
    switch (opc) {
    case INDEX_op_zipl_vec:
    case INDEX_op_ziph_vec:
        return type == TCG_TYPE_V128;
    case INDEX_op_movmsk_vec:
        return type == TCG_TYPE_V128 && (vece == MO_8 || vece == MO_32 || vece == MO_64);
    case INDEX_op_shuf_vec:
        return type == TCG_TYPE_V128 && vece == MO_32;
    case INDEX_op_packss_vec:
        return type == TCG_TYPE_V128 && (vece == MO_8 || vece == MO_16);
    case INDEX_op_packus_vec:
        return type == TCG_TYPE_V128 && vece == MO_8;
    case INDEX_op_fcvt_vec:
    case INDEX_op_fcvti_vec:
        return type == TCG_TYPE_V128 && (vece == MO_32 || vece == MO_64);
    case INDEX_op_fcvts_vec:
        return type == TCG_TYPE_V64 && (vece == MO_32 || vece == MO_64);
    case INDEX_op_fadd_vec:
    case INDEX_op_fsub_vec:
    case INDEX_op_fmul_vec:
    case INDEX_op_fdiv_vec:
    case INDEX_op_fmax_vec:
    case INDEX_op_fmin_vec:
    case INDEX_op_fsqrt_vec:
    case INDEX_op_fsqrts_vec:
    case INDEX_op_ld32_vec:
    case INDEX_op_cvti2f_vec:
    case INDEX_op_cvtf2i_vec:
    case INDEX_op_fcomi_vec:
    case INDEX_op_lane0_vec:
    case INDEX_op_movi2v_vec:
    case INDEX_op_movv2i_vec:
        break;
    default:
        return -1;
    }
    if (type != TCG_TYPE_V64 && type != TCG_TYPE_V128) {
        return 0;
    }
    return (vece == MO_32 || vece == MO_64) ? 1 : 0;
}

static void brov_fp_vec_rrr(TCGContext *s, uint32_t insn, TCGReg d, TCGReg n, TCGReg m)
{
    tcg_out32(s, insn | (((uint32_t)m & 31) << 16) | (((uint32_t)n & 31) << 5) | ((uint32_t)d & 31));
}

static void brov_fp_vec_ins32(TCGContext *s, TCGReg d, unsigned to, TCGReg n, unsigned from)
{
    brov_fp_vec_rrr(s, BROV_INS_S | (to << 19) | (from << 13), d, n, 0);
}

static void brov_fp_vec_ins64(TCGContext *s, TCGReg d, unsigned to, TCGReg n, unsigned from)
{
    brov_fp_vec_rrr(s, BROV_INS_D | (to << 20) | (from << 14), d, n, 0);
}

static void brov_fp_vec_lane0(TCGContext *s, unsigned size, TCGReg out, TCGReg from)
{
    if (size) {
        brov_fp_vec_ins64(s, out, 0, from, 0);
    } else {
        brov_fp_vec_ins32(s, out, 0, from, 0);
    }
}

/* The general case builds the result in the scratch register, because the output may be one of the inputs. */
static void brov_fp_vec_shuf(TCGContext *s, TCGReg out, TCGReg a, TCGReg b, unsigned imm)
{
    unsigned l0 = imm & 3, l1 = (imm >> 2) & 3, l2 = (imm >> 4) & 3, l3 = (imm >> 6) & 3;
    bool one = a == b;
    uint32_t pair = 0, same = 0;

    if (one && l0 == l1 && l0 == l2 && l0 == l3) {
        brov_fp_vec_rrr(s, BROV_DUP_4S | (l0 << 19), out, a, 0);
        return;
    }

    switch (imm) {
    case 0x44: pair = BROV_ZIP1 | (1u << 30) | (3u << 22); break;
    case 0xee: pair = BROV_ZIP2 | (1u << 30) | (3u << 22); break;
    case 0x88: pair = BROV_UZP1 | (1u << 30) | (2u << 22); break;
    case 0xdd: pair = BROV_UZP2 | (1u << 30) | (2u << 22); break;
    case 0x4e: pair = BROV_EXT_8; break;
    case 0x50: same = BROV_ZIP1 | (1u << 30) | (2u << 22); break;
    case 0xfa: same = BROV_ZIP2 | (1u << 30) | (2u << 22); break;
    case 0xa0: same = BROV_TRN1 | (1u << 30) | (2u << 22); break;
    case 0xf5: same = BROV_TRN2 | (1u << 30) | (2u << 22); break;
    case 0xb1: same = BROV_REV64_4S; break;
    default: break;
    }
    if (pair != 0) {
        brov_fp_vec_rrr(s, pair, out, a, b);
        return;
    }
    if (one && same != 0) {
        brov_fp_vec_rrr(s, same, out, a, same == BROV_REV64_4S ? 0 : a);
        return;
    }
    if (imm == 0xe4) {
        if (out != b) {
            tcg_out_mov(s, TCG_TYPE_V128, out, a);
            brov_fp_vec_ins64(s, out, 1, b, 1);
        } else if (!one) {
            brov_fp_vec_ins64(s, out, 0, a, 0);
        }
        return;
    }

    brov_fp_vec_rrr(s, BROV_DUP_4S | (l0 << 19), TCG_VEC_TMP, a, 0);
    if (l1 != l0) {
        brov_fp_vec_ins32(s, TCG_VEC_TMP, 1, a, l1);
    }
    if (!one || l2 != l0) {
        brov_fp_vec_ins32(s, TCG_VEC_TMP, 2, b, l2);
    }
    if (!one || l3 != l0) {
        brov_fp_vec_ins32(s, TCG_VEC_TMP, 3, b, l3);
    }
    tcg_out_mov(s, TCG_TYPE_V128, out, TCG_VEC_TMP);
}

/* The narrowing instruction clears the high half of its output, so the first input goes first,
 * and an output that is also the second input uses the scratch register. */
static void brov_fp_vec_pack(TCGContext *s, uint32_t insn, TCGReg out, TCGReg a, TCGReg b)
{
    TCGReg to = out == b ? TCG_VEC_TMP : out;

    brov_fp_vec_rrr(s, insn, to, a, 0);
    brov_fp_vec_rrr(s, insn | (1u << 30), to, b, 0);
    if (to != out) {
        tcg_out_mov(s, TCG_TYPE_V128, out, to);
    }
}

static bool brov_fp_vec_out(TCGContext *s, TCGOpcode opc, unsigned vecl,
                            unsigned vece, const TCGArg *args)
{
    bool scalar = vecl == 0;
    unsigned size = vece == MO_64;
    TCGReg out = scalar ? TCG_VEC_TMP : args[0];
    int insn;

    switch (opc) {
    case INDEX_op_ld32_vec:
        tcg_out_ld(s, TCG_TYPE_I32, args[0], args[1], args[2]);
        return true;
    case INDEX_op_zipl_vec:
    case INDEX_op_ziph_vec:
        tcg_out_insn_3616(s, (AArch64Insn)(opc == INDEX_op_zipl_vec ? BROV_ZIP1 : BROV_ZIP2), 1, vece,
                          args[0], args[1], args[2]);
        return true;
    case INDEX_op_movmsk_vec: {
        /* Each USRA folds a lane into its neighbour one bit higher, so byte 0 of each half
         * collects the top bits of that half. */
        uint32_t d = (uint32_t)args[0], t = (uint32_t)TCG_VEC_TMP & 31;
        unsigned half;

        if (vece == MO_64) {
            brov_fp_vec_rrr(s, BROV_USHR | ((128 - 63) << 16), TCG_VEC_TMP, args[1], 0);
            tcg_out32(s, BROV_UMOV_D | (t << 5) | d);
            tcg_out32(s, BROV_UMOV_D | (1u << 20) | (t << 5) | TCG_REG_TMP);
            half = 1;
        } else {
            if (vece == MO_8) {
                brov_fp_vec_rrr(s, BROV_USHR | ((16 - 7) << 16), TCG_VEC_TMP, args[1], 0);
                brov_fp_vec_rrr(s, BROV_USRA | ((32 - 7) << 16), TCG_VEC_TMP, TCG_VEC_TMP, 0);
                brov_fp_vec_rrr(s, BROV_USRA | ((64 - 14) << 16), TCG_VEC_TMP, TCG_VEC_TMP, 0);
                brov_fp_vec_rrr(s, BROV_USRA | ((128 - 28) << 16), TCG_VEC_TMP, TCG_VEC_TMP, 0);
                half = 8;
            } else {
                brov_fp_vec_rrr(s, BROV_USHR | ((64 - 31) << 16), TCG_VEC_TMP, args[1], 0);
                brov_fp_vec_rrr(s, BROV_USRA | ((128 - 31) << 16), TCG_VEC_TMP, TCG_VEC_TMP, 0);
                half = 2;
            }
            tcg_out32(s, BROV_UMOV_B | (t << 5) | d);
            tcg_out32(s, BROV_UMOV_B | (8u << 17) | (t << 5) | TCG_REG_TMP);
        }
        tcg_out32(s, BROV_ORR_W_TMP_LSL | (half << 10) | (d << 5) | d);
        return true;
    }
    case INDEX_op_shuf_vec:
        brov_fp_vec_shuf(s, args[0], args[1], args[2], args[3]);
        return true;
    case INDEX_op_packss_vec:
        brov_fp_vec_pack(s, BROV_SQXTN | (vece == MO_16 ? 1u << 22 : 0), args[0], args[1], args[2]);
        return true;
    case INDEX_op_packus_vec:
        brov_fp_vec_pack(s, BROV_SQXTUN, args[0], args[1], args[2]);
        return true;
    case INDEX_op_fcvt_vec:
        brov_fp_vec_rrr(s, size ? BROV_FCVTN : BROV_FCVTL, args[0], args[1], 0);
        return true;
    case INDEX_op_fcvts_vec:
        brov_fp_vec_rrr(s, size ? BROV_FCVT_S_D : BROV_FCVT_D_S, TCG_VEC_TMP, args[2], 0);
        brov_fp_vec_lane0(s, !size, args[0], TCG_VEC_TMP);
        return true;
    case INDEX_op_fcvti_vec:
        if (size) {
            brov_fp_vec_rrr(s, BROV_SXTL_2D, args[0], args[1], 0);
            brov_fp_vec_rrr(s, BROV_SCVTF_2D, args[0], args[0], 0);
        } else {
            brov_fp_vec_rrr(s, BROV_SCVTF_4S, args[0], args[1], 0);
        }
        return true;
    case INDEX_op_lane0_vec:
        brov_fp_vec_lane0(s, size, args[0], args[2]);
        return true;
    case INDEX_op_movi2v_vec:
        tcg_out32(s, (size ? BROV_FMOV_D_X : BROV_FMOV_S_W) | ((uint32_t)args[1] << 5) | ((uint32_t)args[0] & 31));
        return true;
    case INDEX_op_movv2i_vec:
        tcg_out32(s, (size ? BROV_FMOV_X_D : BROV_FMOV_W_S) | (((uint32_t)args[1] & 31) << 5) | (uint32_t)args[0]);
        return true;
    case INDEX_op_cvti2f_vec:
        tcg_out32(s, BROV_SCVTF_W | (args[3] ? 1u << 31 : 0) | (size << 22) |
                         ((uint32_t)args[2] << 5) | ((uint32_t)TCG_VEC_TMP & 31));
        brov_fp_vec_lane0(s, size, args[0], TCG_VEC_TMP);
        return true;
    case INDEX_op_cvtf2i_vec: {
        /* FCVTZS and FCVTNS saturate and give 0 for a NaN, where x86 gives the most negative integer.
         * A 32 bit result is out of range when it is not its own sign extension, and a 64 bit one when
         * it is INT64_MAX, which no float or double is. A NaN fails FCMP, and CCMP then forces that answer. */
        uint32_t d = (uint32_t)args[0], v = (uint32_t)args[1] & 31;
        uint32_t fp = size << 22;

        tcg_out32(s, ((args[2] & 2) ? BROV_FCVTZS_X : BROV_FCVTNS_X) | fp | (v << 5) | d);
        tcg_out32(s, BROV_FCMP | fp | (v << 16) | (v << 5));
        if (args[2] & 1) {
            tcg_out32(s, BROV_MOVN_TMP_I64_MAX);
            tcg_out32(s, BROV_CCMP_TMP_VC | (d << 5) | 4);
            tcg_out32(s, BROV_MOVZ_TMP_I64_MIN);
            tcg_out32(s, BROV_CSEL_X_EQ | (d << 16) | ((uint32_t)TCG_REG_TMP << 5) | d);
        } else {
            tcg_out32(s, BROV_SXTW_TMP | (d << 5));
            tcg_out32(s, BROV_CCMP_TMP_VC | (d << 5));
            tcg_out32(s, BROV_MOVZ_TMP_I32_MIN);
            tcg_out32(s, BROV_CSEL_W_TMP_EQ | (d << 5) | d);
        }
        return true;
    }
    case INDEX_op_fcomi_vec: {
        /* FCMP gives less as LT, unordered as VS and equal as EQ. x86 sets CF
         * for less or unordered, PF for unordered, ZF for equal or unordered. */
        uint32_t d = (uint32_t)args[0];

        tcg_out32(s, BROV_FCMP | (size << 22) | (((uint32_t)args[2] & 31) << 16) |
                         (((uint32_t)args[1] & 31) << 5));
        tcg_out32(s, BROV_CSET_LT | d);
        tcg_out32(s, BROV_CSET_TMP_VS);
        tcg_out32(s, BROV_ORR_W_TMP_LSL | (2 << 10) | (d << 5) | d);
        tcg_out32(s, BROV_CSINC_TMP_NE);
        tcg_out32(s, BROV_ORR_W_TMP_LSL | (6 << 10) | (d << 5) | d);
        return true;
    }
    case INDEX_op_fsqrt_vec:
        tcg_out_insn_3617(s, (AArch64Insn)BROV_FSQRT_V, 1, size, args[0], args[1]);
        return true;
    case INDEX_op_fsqrts_vec:
        tcg_out_insn_3617(s, (AArch64Insn)BROV_FSQRT_S, 0, size, TCG_VEC_TMP, args[2]);
        brov_fp_vec_lane0(s, size, args[0], TCG_VEC_TMP);
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
        if (scalar) {
            brov_fp_vec_lane0(s, size, args[0], TCG_VEC_TMP);
        } else {
            tcg_out_mov(s, TCG_TYPE_V128, args[0], TCG_VEC_TMP);
        }
        return true;
    }
    case INDEX_op_fadd_vec: insn = scalar ? BROV_FADD_S : BROV_FADD_V; break;
    case INDEX_op_fsub_vec: insn = scalar ? BROV_FSUB_S : BROV_FSUB_V; break;
    case INDEX_op_fmul_vec: insn = scalar ? BROV_FMUL_S : BROV_FMUL_V; break;
    case INDEX_op_fdiv_vec: insn = scalar ? BROV_FDIV_S : BROV_FDIV_V; break;
    default:
        return false;
    }
    tcg_out_insn_3616(s, (AArch64Insn)insn, !scalar, size, out, args[1], args[2]);
    if (scalar) {
        brov_fp_vec_lane0(s, size, args[0], TCG_VEC_TMP);
    }
    return true;
}

#endif
