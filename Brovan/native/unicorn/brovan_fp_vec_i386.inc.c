/* Emitters for the opcodes in brovan_fp_vec_opc.inc.h.
 *
 * The packed and scalar forms differ only in the mandatory prefix, so one table
 * per operation covers ps, pd, ss and sd. A VEX scalar instruction takes the
 * lanes above lane 0 from vvvv, which is the first input of the scalar form. */
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
static const TCGTargetOpDef brov_x_x_r = { .args_ct_str = { "x", "x", "r" } };
static const TCGTargetOpDef brov_r_x = { .args_ct_str = { "r", "x" } };
/* LAHF leaves the flags of the compare in AH. */
static const TCGTargetOpDef brov_a_x_x = { .args_ct_str = { "a", "x", "x" } };

static const TCGTargetOpDef *brov_fp_vec_op_def(TCGOpcode op)
{
    switch (op) {
    case INDEX_op_cvti2f_vec:
        return &brov_x_x_r;
    case INDEX_op_cvtf2i_vec:
    case INDEX_op_movv2i_vec:
    case INDEX_op_movmsk_vec:
        return &brov_r_x;
    case INDEX_op_fcomi_vec:
        return &brov_a_x_x;
    case INDEX_op_fadd_vec:
    case INDEX_op_fsub_vec:
    case INDEX_op_fmul_vec:
    case INDEX_op_fdiv_vec:
    case INDEX_op_fmax_vec:
    case INDEX_op_fmin_vec:
    case INDEX_op_fsqrts_vec:
    case INDEX_op_lane0_vec:
    case INDEX_op_zipl_vec:
    case INDEX_op_ziph_vec:
    case INDEX_op_fcvts_vec:
    case INDEX_op_shuf_vec:
    case INDEX_op_packss_vec:
    case INDEX_op_packus_vec:
        return &brov_x_x_x;
    case INDEX_op_fsqrt_vec:
    case INDEX_op_fcvt_vec:
    case INDEX_op_fcvti_vec:
        return &brov_x_x;
    case INDEX_op_ld32_vec:
    case INDEX_op_movi2v_vec:
        return &brov_x_r;
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
        return have_avx1 && type == TCG_TYPE_V128;
    case INDEX_op_movmsk_vec:
        return have_avx1 && type == TCG_TYPE_V128 && (vece == MO_8 || vece == MO_32 || vece == MO_64);
    case INDEX_op_shuf_vec:
        return have_avx1 && type == TCG_TYPE_V128 && vece == MO_32;
    case INDEX_op_packss_vec:
        return have_avx1 && type == TCG_TYPE_V128 && (vece == MO_8 || vece == MO_16);
    case INDEX_op_packus_vec:
        return have_avx1 && type == TCG_TYPE_V128 && vece == MO_8;
    case INDEX_op_fcvt_vec:
    case INDEX_op_fcvti_vec:
        return have_avx1 && type == TCG_TYPE_V128 && (vece == MO_32 || vece == MO_64);
    case INDEX_op_fcvts_vec:
        return have_avx1 && type == TCG_TYPE_V64 && (vece == MO_32 || vece == MO_64);
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
    static const int max_fp[4] = BROV_FP_OPC(0x5f);
    static const int min_fp[4] = BROV_FP_OPC(0x5d);
    static const int cvt_fp[4] = BROV_FP_OPC(0x5a);

    int scalar = vecl == 0;
    int wide = vece == MO_64;
    int idx = scalar * 2 + wide;
    int insn;

    switch (opc) {
    case INDEX_op_ld32_vec:
        tcg_out_ld(s, TCG_TYPE_I32, args[0], args[1], args[2]);
        return true;
    case INDEX_op_zipl_vec:
    case INDEX_op_ziph_vec: {
        /* VPUNPCKL and VPUNPCKH, by lane size. */
        static const uint8_t low[4] = { 0x60, 0x61, 0x62, 0x6c };
        static const uint8_t high[4] = { 0x68, 0x69, 0x6a, 0x6d };

        insn = (opc == INDEX_op_zipl_vec ? low : high)[vece] | P_EXT | P_DATA16;
        tcg_out_vex_modrm(s, insn, args[0], args[1], args[2]);
        return true;
    }
    case INDEX_op_movmsk_vec:
        /* VPMOVMSKB, VMOVMSKPS and VMOVMSKPD. */
        insn = vece == MO_8 ? 0xd7 | P_EXT | P_DATA16 : 0x50 | P_EXT | (wide ? P_DATA16 : 0);
        tcg_out_vex_modrm(s, insn, args[0], 0, args[1]);
        return true;
    case INDEX_op_shuf_vec:
        /* VSHUFPS. */
        tcg_out_vex_modrm(s, 0xc6 | P_EXT, args[0], args[1], args[2]);
        tcg_out8(s, args[3]);
        return true;
    case INDEX_op_packss_vec:
        /* VPACKSSWB and VPACKSSDW. */
        tcg_out_vex_modrm(s, (vece == MO_8 ? 0x63 : 0x6b) | P_EXT | P_DATA16, args[0], args[1], args[2]);
        return true;
    case INDEX_op_packus_vec:
        /* VPACKUSWB. */
        tcg_out_vex_modrm(s, 0x67 | P_EXT | P_DATA16, args[0], args[1], args[2]);
        return true;
    case INDEX_op_fcvt_vec:
        /* VCVTPS2PD and VCVTPD2PS. */
        tcg_out_vex_modrm(s, cvt_fp[wide], args[0], 0, args[1]);
        return true;
    case INDEX_op_fcvts_vec:
        /* VCVTSS2SD and VCVTSD2SS. */
        tcg_out_vex_modrm(s, cvt_fp[2 + wide], args[0], args[1], args[2]);
        return true;
    case INDEX_op_fcvti_vec:
        /* VCVTDQ2PS and VCVTDQ2PD. */
        tcg_out_vex_modrm(s, wide ? 0xe6 | P_EXT | P_SIMDF3 : 0x5b | P_EXT, args[0], 0, args[1]);
        return true;
    case INDEX_op_lane0_vec:
        /* VMOVSS and VMOVSD between registers. */
        tcg_out_vex_modrm(s, 0x10 | P_EXT | (wide ? P_SIMDF2 : P_SIMDF3), args[0], args[1], args[2]);
        return true;
    case INDEX_op_movi2v_vec:
        tcg_out_vex_modrm(s, OPC_MOVD_VyEy | (wide ? P_REXW : 0), args[0], 0, args[1]);
        return true;
    case INDEX_op_movv2i_vec:
        tcg_out_vex_modrm(s, OPC_MOVD_EyVy | (wide ? P_REXW : 0), args[1], 0, args[0]);
        return true;
    case INDEX_op_cvti2f_vec:
        /* VCVTSI2SS and VCVTSI2SD. */
        insn = 0x2a | P_EXT | (wide ? P_SIMDF2 : P_SIMDF3) | (args[3] ? P_REXW : 0);
        tcg_out_vex_modrm(s, insn, args[0], args[1], args[2]);
        return true;
    case INDEX_op_cvtf2i_vec:
        /* VCVTTSx2SI and VCVTSx2SI, which already give the x86 answer for a NaN or a value out of range. */
        insn = ((args[2] & 2) ? 0x2c : 0x2d) | P_EXT |
               (wide ? P_SIMDF2 : P_SIMDF3) | ((args[2] & 1) ? P_REXW : 0);
        tcg_out_vex_modrm(s, insn, args[0], 0, args[1]);
        return true;
    case INDEX_op_fcomi_vec:
        /* VUCOMISx, then LAHF, MOVZBL %AH,%EAX and ANDL $0x45,%EAX. */
        tcg_out_vex_modrm(s, 0x2e | P_EXT | (wide ? P_DATA16 : 0), args[1], 0, args[2]);
        tcg_out8(s, 0x9f);
        tcg_out8(s, 0x0f);
        tcg_out8(s, 0xb6);
        tcg_out8(s, 0xc4);
        tcg_out8(s, 0x83);
        tcg_out8(s, 0xe0);
        tcg_out8(s, 0x45);
        return true;
    case INDEX_op_fsqrt_vec:
        tcg_out_vex_modrm(s, sqrt_fp[wide], args[0], 0, args[1]);
        return true;
    case INDEX_op_fsqrts_vec: insn = sqrt_fp[2 + wide]; break;
    case INDEX_op_fadd_vec: insn = add_fp[idx]; break;
    case INDEX_op_fsub_vec: insn = sub_fp[idx]; break;
    case INDEX_op_fmul_vec: insn = mul_fp[idx]; break;
    case INDEX_op_fdiv_vec: insn = div_fp[idx]; break;
    case INDEX_op_fmax_vec: insn = max_fp[idx]; break;
    case INDEX_op_fmin_vec: insn = min_fp[idx]; break;
    default:
        return false;
    }
    tcg_out_vex_modrm(s, insn, args[0], args[1], args[2]);
    return true;
}

#endif
