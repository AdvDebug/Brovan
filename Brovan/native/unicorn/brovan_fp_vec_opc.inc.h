/* TCG has no floating point opcodes in any QEMU version, so SSE add, subtract,
 * multiply, divide and square root leave the block for a helper call. These give
 * a host backend a way to emit the instruction instead.
 *
 * TCG_TYPE_V64 selects the scalar form: only lane 0 is defined and the backend
 * emits the host scalar instruction. ld32_vec and st32_vec carry lane 0 alone,
 * which is what a single precision scalar destination needs. They come as a
 * pair: a 4 byte store feeding an 8 byte load of the same address does not
 * forward on x86 and costs more than the helper call this replaces.
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
DEF(ld32_vec, 1, 1, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
DEF(st32_vec, 0, 2, 1, IMPLVEC | IMPL(TCG_TARGET_HAS_brov_fpvec))
