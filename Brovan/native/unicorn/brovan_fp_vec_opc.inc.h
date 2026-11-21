/* TCG has no floating point opcodes in any QEMU version, so SSE add, subtract,
 * multiply, divide and square root leave the block for a helper call. These give
 * a host backend a way to emit the instruction instead.
 *
 * TCG_TYPE_V64 selects the scalar form, where the other lanes of the output
 * come from the first input.
 *
 * fmax_vec and fmin_vec are x86 max and min, not the ARM operations of the
 * same name: an unordered or equal pair gives the second operand.
 *
 * ld32_vec loads 4 bytes of env into lane 0, because a 4 byte store does not
 * forward to a wider load.
 *
 * No include guard. tcg-opc.h is read once per DEF macro. */
#ifndef TCG_TARGET_HAS_brov_fpvec
#define TCG_TARGET_HAS_brov_fpvec 0
#endif

DEF(fadd_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fsub_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fmul_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fdiv_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fsqrt_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fsqrts_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fmax_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fmin_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(ld32_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))

/* The first input with the integer register converted into lane 0. The constant is 1 for a 64 bit source. */
DEF(cvti2f_vec, 1, 2, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
/* A NaN or a value out of range gives the most negative integer, as on x86. Constant bit 0 selects a
 * 64 bit result, and bit 1 truncation instead of round to nearest even. */
DEF(cvtf2i_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
/* ZF, PF and CF of ucomis at their EFLAGS positions, every other bit clear. */
DEF(fcomi_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))

/* The element size is the size of a source lane. Doubles narrow into the low half and zero the high half,
 * and singles or 32 bit integers widen from the low half. */
DEF(fcvt_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fcvts_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(fcvti_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))

/* lane0_vec gives the first input with lane 0 of the second. movi2v_vec zeroes the other lanes. */
DEF(lane0_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(movi2v_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(movv2i_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))

/* x86 pmovmskb, movmskps and movmskpd. */
DEF(movmsk_vec, 1, 1, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))

/* x86 punpckl and punpckh. */
DEF(zipl_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(ziph_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))

/* x86 shufps: output lanes 0 and 1 come from the first input, lanes 2 and 3 from the second. */
DEF(shuf_vec, 1, 2, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))

/* x86 packss and packus. The element size is the size of an output lane. */
DEF(packss_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(packus_vec, 1, 2, 0, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))

/* The constants are the env offset that the slow path passes the value through, and the mmu index. */
#ifndef TCG_TARGET_HAS_brov_vecmem
#define TCG_TARGET_HAS_brov_vecmem 0
#endif

DEF(qemu_ld_v128, 1, 1, 2, TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT | IMPL(TCG_TARGET_HAS_brov_vecmem))
DEF(qemu_st_v128, 0, 2, 2, TCG_OPF_CALL_CLOBBER | TCG_OPF_SIDE_EFFECTS | TCG_OPF_64BIT | IMPL(TCG_TARGET_HAS_brov_vecmem))

/* Stores every dirty XMM global to env, and leaves none of them in a host register. */
DEF(sync_xmm, 0, 0, 0, TCG_OPF_NOT_PRESENT)
/* The last op of an instruction that has sync_xmm. */
DEF(sync_xmm_end, 0, 0, 0, TCG_OPF_NOT_PRESENT)

/* The constant is the flags of the block that asks. */
#ifndef TCG_TARGET_HAS_brov_jmpstub
#define TCG_TARGET_HAS_brov_jmpstub 0
#endif

DEF(lookup_tb_stub, 1, 0, 1, TCG_OPF_CALL_CLOBBER | TCG_OPF_64BIT | IMPL(TCG_TARGET_HAS_brov_jmpstub))
