/* A pinned guest register lives in its host register while translated code runs, and in env whenever C code
 * can see it. tcg_out_call syncs both ways unless the caller narrowed it, so a path into C that skips
 * tcg_out_call syncs the pins itself. */
#ifndef BROVAN_TCG_PIN_INC_H
#define BROVAN_TCG_PIN_INC_H

#ifndef TCG_TARGET_HAS_brov_pin
#define TCG_TARGET_HAS_brov_pin 0
#endif

#define BROV_PIN_SPILL 1
#define BROV_PIN_RELOAD 2
/* A hot call site syncs in place rather than through the shared stubs. */
#define BROV_PIN_INLINE 4
/* Without this flag a call syncs both ways. */
#define BROV_PIN_CHOSEN 8
#define BROV_PIN_BUSY 16

static inline bool brov_pin_is_env(const TCGTemp *ts)
{
    return ts->fixed_reg && ts->reg == TCG_AREG0;
}

#if TCG_TARGET_HAS_brov_pin

#if defined(TARGET_X86_64)
/* A host with fewer registers pins the head of the list, so the busiest registers come first. */
static const int32_t brov_pin_slots[] = {
    offsetof(CPUX86State, regs[R_ESP]), offsetof(CPUX86State, regs[R_EAX]),
    offsetof(CPUX86State, regs[R_ECX]), offsetof(CPUX86State, regs[R_EDX]),
    offsetof(CPUX86State, regs[R_EBX]), offsetof(CPUX86State, regs[R_ESI]),
    offsetof(CPUX86State, regs[R_EDI]), offsetof(CPUX86State, regs[R_EBP]),
};
#define BROV_PIN_SLOT_COUNT ARRAY_SIZE(brov_pin_slots)
#else
static const int32_t brov_pin_slots[1];
#define BROV_PIN_SLOT_COUNT 0
#endif

static void brov_pin_emit(TCGContext *s, bool load);
static void brov_pin_emit_far(TCGContext *s, bool load);
static TCGTemp *tcg_global_reg_new_internal(TCGContext *s, TCGType type, TCGReg reg, const char *name);
static TCGReg tcg_reg_alloc(TCGContext *s, TCGRegSet required_regs, TCGRegSet allocated_regs,
                            TCGRegSet preferred_regs, bool rev);
static inline void temp_dead(TCGContext *s, TCGTemp *ts);

static void brov_pin_setup(TCGContext *s, const TCGReg *regs, unsigned count)
{
    unsigned i, j;

    s->brov_pin_count = 0;
    if (getenv("BROVAN_NO_PIN") != NULL) {
        return;
    }
    /* Kept in slot order, so an emitter finds neighbouring slots next to each other. */
    for (i = 0; i < count && i < BROV_PIN_SLOT_COUNT && i < BROV_PIN_MAX; i++) {
        int32_t ofs = brov_pin_slots[i];

        for (j = i; j > 0 && s->brov_pin_ofs[j - 1] > ofs; j--) {
            s->brov_pin_ofs[j] = s->brov_pin_ofs[j - 1];
        }
        s->brov_pin_ofs[j] = ofs;
        s->brov_pin_reg[i] = regs[i];
        tcg_regset_set_reg(s->reserved_regs, regs[i]);
    }
    s->brov_pin_count = i;
}

static TCGTemp *brov_pin_global(TCGContext *s, TCGType type, TCGv_ptr base, intptr_t offset, const char *name)
{
    TCGTemp *base_ts = tcgv_ptr_temp(s, base);
    unsigned i;

    if (type != TCG_TYPE_TL || !base_ts->fixed_reg || base_ts->reg != TCG_AREG0) {
        return NULL;
    }
    for (i = 0; i < s->brov_pin_count; i++) {
        if (s->brov_pin_ofs[i] == offset) {
            return tcg_global_reg_new_internal(s, type, s->brov_pin_reg[i], name);
        }
    }
    return NULL;
}

/* A pin holds its value in its own register, whatever liveness says about dead or sync. */
static bool brov_pin_movi(TCGContext *s, TCGTemp *ots, tcg_target_ulong val)
{
    if (!ots->fixed_reg) {
        return false;
    }
    tcg_out_movi(s, ots->type, ots->reg, val);
    return true;
}

static bool brov_pin_mov(TCGContext *s, TCGTemp *ots, TCGTemp *ts, bool source_dead)
{
    if (!ots->fixed_reg) {
        return false;
    }
    tcg_out_mov(s, ots->type, ots->reg, ts->reg);
    if (source_dead) {
        temp_dead(s, ts);
    }
    return true;
}

static TCGReg brov_pin_out_reg(TCGContext *s, const TCGTemp *ts, const TCGArgConstraint *ct, const int *const_args,
                               const TCGArg *new_args, TCGRegSet i_allocated, TCGRegSet *o_allocated,
                               TCGRegSet preferred)
{
    TCGReg reg;

    if ((ct->ct & TCG_CT_ALIAS) && !const_args[ct->alias_index]) {
        reg = new_args[ct->alias_index];
    } else if (ct->ct & TCG_CT_NEWREG) {
        reg = tcg_reg_alloc(s, ct->u.regs, i_allocated | *o_allocated, preferred, false);
    } else if (tcg_regset_test_reg(ct->u.regs, ts->reg)) {
        reg = ts->reg;
    } else {
        reg = tcg_reg_alloc(s, ct->u.regs, *o_allocated, preferred, false);
    }
    tcg_regset_set_reg(*o_allocated, reg);
    return reg;
}

static void brov_pin_out_moves(TCGContext *s, const TCGOp *op, int nb_oargs, const TCGArg *new_args)
{
    int i;

    for (i = 0; i < nb_oargs; i++) {
        TCGTemp *ts = arg_temp(op->args[i]);

        if (ts->fixed_reg && ts->reg != new_args[i]) {
            tcg_out_mov(s, ts->type, ts->reg, new_args[i]);
        }
    }
}

static bool brov_pin_call_out(TCGContext *s, TCGTemp *ts, TCGReg reg)
{
    if (!ts->fixed_reg) {
        return false;
    }
    tcg_out_mov(s, ts->type, ts->reg, reg);
    return true;
}

static void brov_pin_helper_call(TCGContext *s, int flags)
{
    if (s->brov_pin_count == 0) {
        return;
    }
    if (flags & TCG_CALL_NO_READ_GLOBALS) {
        s->brov_pin_sync = BROV_PIN_CHOSEN;
    } else if (flags & (TCG_CALL_NO_WRITE_GLOBALS | TCG_CALL_NO_RETURN)) {
        s->brov_pin_sync = BROV_PIN_CHOSEN | BROV_PIN_INLINE | BROV_PIN_SPILL;
    } else {
        s->brov_pin_sync = BROV_PIN_CHOSEN | BROV_PIN_INLINE | BROV_PIN_SPILL | BROV_PIN_RELOAD;
    }
}

/* The reload sits inside the call, so it comes before the caller moves a result. */
static bool brov_pin_call(TCGContext *s, tcg_insn_unit *target)
{
    unsigned sync = s->brov_pin_sync;
    void (*emit)(TCGContext *, bool);

    if (sync & BROV_PIN_BUSY) {
        return false;
    }
    s->brov_pin_sync = 0;
    if (s->brov_pin_count == 0) {
        return false;
    }
    if (!(sync & BROV_PIN_CHOSEN)) {
        sync = BROV_PIN_SPILL | BROV_PIN_RELOAD;
    }

    emit = (sync & BROV_PIN_INLINE) ? brov_pin_emit : brov_pin_emit_far;
    s->brov_pin_sync = BROV_PIN_BUSY;
    if (sync & BROV_PIN_SPILL) {
        emit(s, false);
    }
    tcg_out_call(s, target);
    if (sync & BROV_PIN_RELOAD) {
        emit(s, true);
    }
    s->brov_pin_sync = 0;
    return true;
}

#else

static inline TCGTemp *brov_pin_global(TCGContext *s, TCGType type, TCGv_ptr base, intptr_t offset, const char *name)
{
    return NULL;
}

static inline bool brov_pin_movi(TCGContext *s, TCGTemp *ots, tcg_target_ulong val)
{
    return false;
}

static inline bool brov_pin_mov(TCGContext *s, TCGTemp *ots, TCGTemp *ts, bool source_dead)
{
    return false;
}

static inline TCGReg brov_pin_out_reg(TCGContext *s, const TCGTemp *ts, const TCGArgConstraint *ct,
                                      const int *const_args, const TCGArg *new_args, TCGRegSet i_allocated,
                                      TCGRegSet *o_allocated, TCGRegSet preferred)
{
    return ts->reg;
}

static inline void brov_pin_out_moves(TCGContext *s, const TCGOp *op, int nb_oargs, const TCGArg *new_args)
{
}

static inline bool brov_pin_call_out(TCGContext *s, TCGTemp *ts, TCGReg reg)
{
    return false;
}

static inline void brov_pin_helper_call(TCGContext *s, int flags)
{
}

#endif

#endif
