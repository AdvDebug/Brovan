/* Only the slow path of a guest memory op calls C, so the op frees just the registers its fast path
 * writes, and the slow path saves the other live call-clobbered registers around the helper. */
#ifndef BROVAN_TCG_LDST_KEEP_INC_H
#define BROVAN_TCG_LDST_KEEP_INC_H

#define BROV_LDST_KEEP_SLOT 16
#define BROV_LDST_KEEP_BYTES (TCG_TARGET_NB_REGS * BROV_LDST_KEEP_SLOT)

/* The inputs of a guest memory op stay out of the registers its fast path writes, so the registers
 * that no input may use are those scratch registers. */
static TCGRegSet brov_ldst_keep_scratch(const TCGContext *s, TCGOpcode opc)
{
    const TCGTargetOpDef *target = tcg_target_op_def(opc);
    const TCGOpDef *def = &s->tcg_op_defs[opc];
    TCGRegSet usable = 0;
    int i;

    if (target == NULL) {
        return 0;
    }
    for (i = def->nb_oargs; i < def->nb_oargs + def->nb_iargs; i++) {
        const char *ct_str = target->args_ct_str[i];

        while (ct_str != NULL && *ct_str != '\0') {
            TCGArgConstraint ct = { 0 };

            ct_str = target_parse_constraint(&ct, ct_str, TCG_TYPE_REG);
            usable |= ct.u.regs;
        }
        if (ct_str == NULL) {
            return 0;
        }
    }
    return s->tcg_target_available_regs[TCG_TYPE_REG] & ~usable;
}

static void brov_ldst_keep_setup(TCGContext *s)
{
    const TCGRegSet scratch = brov_ldst_keep_scratch(s, INDEX_op_qemu_st_i64);
    const TCGRegSet scratch_wide = brov_ldst_keep_scratch(s, INDEX_op_qemu_st_v128);

    if (scratch == 0 || scratch_wide == 0 || getenv("BROVAN_NO_LDST_KEEP") != NULL) {
        return;
    }
    s->brov_ldst_kept = s->tcg_target_call_clobber_regs & ~(scratch | scratch_wide);
}

static TCGRegSet brov_ldst_keep_set(const TCGContext *s, TCGOpcode opc)
{
    switch (opc) {
    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_ld_i64:
    case INDEX_op_qemu_st_i64:
    case INDEX_op_qemu_ld_v128:
    case INDEX_op_qemu_st_v128:
        return s->brov_ldst_kept;
    default:
        return 0;
    }
}

static TCGRegSet brov_ldst_keep_clobber(const TCGContext *s, TCGOpcode opc)
{
    return s->tcg_target_call_clobber_regs & ~brov_ldst_keep_set(s, opc);
}

/* A save slot holds 16 bytes. A wider value is freed, as at a call. */
static bool brov_ldst_keep_frees(const TCGContext *s, TCGOpcode opc, TCGReg reg)
{
    const TCGTemp *ts = s->reg_to_temp[reg];

    return !tcg_regset_test_reg(brov_ldst_keep_set(s, opc), reg) || (ts != NULL && ts->type == TCG_TYPE_V256);
}

/* An output gets its value from the op, so the slow path does not keep it. */
static void brov_ldst_keep_note(TCGContext *s, const TCGOp *op, const TCGArg *new_args)
{
    const TCGRegSet kept = brov_ldst_keep_set(s, op->opc);
    TCGRegSet live = 0;
    int i;

    if (kept != 0) {
        for (i = 0; i < TCG_TARGET_NB_REGS; i++) {
            if (tcg_regset_test_reg(kept, i) && s->reg_to_temp[i] != NULL) {
                tcg_regset_set_reg(live, i);
            }
        }
        for (i = 0; i < s->tcg_op_defs[op->opc].nb_oargs; i++) {
            tcg_regset_reset_reg(live, new_args[i]);
        }
    }
    s->brov_ldst_live = live;
}

static void brov_ldst_keep_emit(TCGContext *s, TCGRegSet regs, bool save)
{
    const TCGRegSet vectors = s->tcg_target_available_regs[TCG_TYPE_V128];
    int reg;

    for (reg = 0; reg < TCG_TARGET_NB_REGS; reg++) {
        const TCGType type = tcg_regset_test_reg(vectors, reg) ? TCG_TYPE_V128 : TCG_TYPE_REG;
        const intptr_t ofs = s->frame_end + reg * BROV_LDST_KEEP_SLOT;

        if (!tcg_regset_test_reg(regs, reg)) {
            continue;
        }
        if (save) {
            tcg_out_st(s, type, reg, TCG_REG_CALL_STACK, ofs);
        } else {
            tcg_out_ld(s, type, reg, TCG_REG_CALL_STACK, ofs);
        }
    }
}

#endif
