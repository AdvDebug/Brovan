/* A pinned guest register lives in its host register while translated code runs, and in env whenever C code
 * can see it. tcg_out_call syncs both ways unless the caller narrowed it, so a path into C that skips
 * tcg_out_call syncs the pins itself, with brov_pin_sync_masks.
 * A held pin (brov_pin_env_held) is in env and its register is garbage until brov_pin_before_op loads it back. */
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
#define BROV_PIN_SPILL_CALLER 32
#define BROV_PIN_RELOAD_CALLER 64
/* The pins of brov_pin_lazy_ok stay held after the call instead of coming back. */
#define BROV_PIN_RELOAD_LAZY 128

typedef struct {
    int32_t ofs;
    TCGType type;
    /* The reload after a call may wait for the first use. A pin that backend code reads without an op naming it
     * must not wait. */
    bool lazy;
} brov_pin_slot;

typedef struct {
    TCGReg reg;
    bool caller_saved;
} brov_pin_host_reg;

static inline bool brov_pin_is_env(const TCGTemp *ts)
{
    return ts->fixed_reg && ts->reg == TCG_AREG0;
}

/* Code after the last exit is reached only past a call that does not return, so pins can still be held there. */
static void brov_pin_env_check_end(TCGContext *s)
{
    if (s->brov_pin_env_span != 0) {
        tcg_abort();
    }
    s->brov_pin_env_held = 0;
}

#if TCG_TARGET_HAS_brov_pin

#if defined(TARGET_X86_64)
/* A host with fewer registers pins the head of the list, so the busiest registers come first. */
static const brov_pin_slot brov_pin_slots[] = {
    { offsetof(CPUX86State, regs[R_ESP]), TCG_TYPE_TL, false },
    { offsetof(CPUX86State, regs[R_EAX]), TCG_TYPE_TL, false },
    { offsetof(CPUX86State, regs[R_ECX]), TCG_TYPE_TL, false },
    { offsetof(CPUX86State, regs[R_EDX]), TCG_TYPE_TL, false },
    { offsetof(CPUX86State, regs[R_EBX]), TCG_TYPE_TL, false },
    { offsetof(CPUX86State, regs[R_ESI]), TCG_TYPE_TL, false },
    { offsetof(CPUX86State, regs[R_EDI]), TCG_TYPE_TL, false },
    { offsetof(CPUX86State, regs[R_EBP]), TCG_TYPE_TL, false },
    { BROV_BUDGET_OFF, TCG_TYPE_I32, false },
    { offsetof(CPUX86State, xmm_regs[0]), TCG_TYPE_V128, true },
    { offsetof(CPUX86State, xmm_regs[1]), TCG_TYPE_V128, true },
    { offsetof(CPUX86State, xmm_regs[2]), TCG_TYPE_V128, true },
};
#define BROV_PIN_SLOT_COUNT ARRAY_SIZE(brov_pin_slots)
#else
static const brov_pin_slot brov_pin_slots[1];
#define BROV_PIN_SLOT_COUNT 0
#endif

static void brov_pin_emit(TCGContext *s, bool load, uint32_t mask);
static void brov_pin_emit_far(TCGContext *s, bool load, uint32_t mask);
static TCGTemp *tcg_global_reg_new_internal(TCGContext *s, TCGType type, TCGReg reg, const char *name);
static TCGReg tcg_reg_alloc(TCGContext *s, TCGRegSet required_regs, TCGRegSet allocated_regs,
                            TCGRegSet preferred_regs, bool rev);
static inline void temp_dead(TCGContext *s, TCGTemp *ts);

/* Each slot takes the next free host register of its own class, so the busiest slots get the callee-saved ones. */
static void brov_pin_setup(TCGContext *s, const brov_pin_host_reg *regs, unsigned count)
{
    const char *gate = getenv("BROVAN_NO_PIN");
    bool callee_only = gate != NULL && strcmp(gate, "caller") == 0;
    bool no_vector = gate != NULL && strcmp(gate, "vector") == 0;
    bool used[BROV_PIN_MAX * 2] = { false };
    bool caller[BROV_PIN_MAX] = { false };
    bool lazy[BROV_PIN_MAX] = { false };
    unsigned i, j, n = 0;

    QEMU_BUILD_BUG_ON(BROV_PIN_MAX > sizeof(s->brov_pin_all) * 8);
    s->brov_pin_count = 0;
    s->brov_pin_all = 0;
    s->brov_pin_caller = 0;
    s->brov_pin_lazy_ok = 0;
    s->brov_pin_env_held = 0;
    s->brov_pin_env_span = 0;
    memset(s->brov_pin_reg_mask, 0, sizeof(s->brov_pin_reg_mask));
    if (gate != NULL && !callee_only && !no_vector) {
        return;
    }
    for (i = 0; i < BROV_PIN_SLOT_COUNT && n < BROV_PIN_MAX; i++) {
        const brov_pin_slot *slot = &brov_pin_slots[i];
        unsigned r;

        /* The XMM globals give a pinned XMM register its sync_xmm. */
        if (slot->type == TCG_TYPE_V128 && (no_vector || !s->brov_xmm_on || !TCG_TARGET_HAS_v128)) {
            continue;
        }
        for (r = 0; r < count && r < ARRAY_SIZE(used); r++) {
            if (!used[r] && !(callee_only && regs[r].caller_saved) &&
                tcg_regset_test_reg(s->tcg_target_available_regs[slot->type], regs[r].reg)) {
                break;
            }
        }
        if (r == count || r == ARRAY_SIZE(used)) {
            continue;
        }
        used[r] = true;

        /* Kept in offset order, so an emitter finds neighbouring slots next to each other. */
        for (j = n; j > 0 && s->brov_pin_ofs[j - 1] > slot->ofs; j--) {
            s->brov_pin_ofs[j] = s->brov_pin_ofs[j - 1];
            s->brov_pin_reg[j] = s->brov_pin_reg[j - 1];
            s->brov_pin_type[j] = s->brov_pin_type[j - 1];
            caller[j] = caller[j - 1];
            lazy[j] = lazy[j - 1];
        }
        s->brov_pin_ofs[j] = slot->ofs;
        s->brov_pin_reg[j] = regs[r].reg;
        s->brov_pin_type[j] = slot->type;
        caller[j] = regs[r].caller_saved;
        lazy[j] = slot->lazy && regs[r].caller_saved;
        tcg_regset_set_reg(s->reserved_regs, regs[r].reg);
        n++;
    }
    for (i = 0; i < n; i++) {
        uint32_t bit = 1u << i;

        s->brov_pin_all |= bit;
        s->brov_pin_reg_mask[s->brov_pin_reg[i]] = bit;
        if (caller[i]) {
            s->brov_pin_caller |= bit;
        }
        if (lazy[i]) {
            s->brov_pin_lazy_ok |= bit;
        }
    }
    s->brov_pin_count = n;
}

static uint32_t brov_pin_mask_of(TCGContext *s, TCGReg reg)
{
    return s->brov_pin_reg_mask[reg];
}

/* Until brov_pin_env_end, env holds the pins in mask whatever the ops do, and no call saves or restores them. */
static void brov_pin_env_begin(TCGContext *s, uint32_t mask)
{
    if (s->brov_pin_env_span != 0) {
        tcg_abort();
    }
    brov_pin_emit(s, false, mask & ~s->brov_pin_env_held);
    s->brov_pin_env_held |= mask;
    s->brov_pin_env_span = mask;
}

static void brov_pin_env_end(TCGContext *s)
{
    s->brov_pin_env_span = 0;
}

static bool brov_pin_op_names(TCGContext *s, const TCGOp *op, uint32_t mask)
{
    const TCGOpDef *def = &s->tcg_op_defs[op->opc];
    int i;

    for (i = 0; i < def->nb_oargs + def->nb_iargs; i++) {
        const TCGTemp *ts = arg_temp(op->args[i]);

        if (ts->fixed_reg && (brov_pin_mask_of(s, ts->reg) & mask) != 0) {
            return true;
        }
    }
    return false;
}

/* The next block expects every pin in its register, so no span may be open at a block exit. */
static void brov_pin_before_op(TCGContext *s, const TCGOp *op)
{
    int flags = s->tcg_op_defs[op->opc].flags;
    bool exit = op->opc == INDEX_op_lookup_tb_stub || (flags & TCG_OPF_BB_EXIT) != 0;
    uint32_t loose = s->brov_pin_env_held & ~s->brov_pin_env_span;

    if (exit && s->brov_pin_env_span != 0) {
        tcg_abort();
    }
    if (loose != 0 && (exit || (flags & TCG_OPF_BB_END) != 0 || brov_pin_op_names(s, op, loose))) {
        brov_pin_emit(s, true, loose);
        s->brov_pin_env_held &= ~loose;
    }
}

static TCGTemp *brov_pin_global(TCGContext *s, TCGType type, TCGv_ptr base, intptr_t offset, const char *name)
{
    TCGTemp *base_ts = tcgv_ptr_temp(s, base);
    unsigned i;

    if (!base_ts->fixed_reg || base_ts->reg != TCG_AREG0) {
        return NULL;
    }
    for (i = 0; i < s->brov_pin_count; i++) {
        if (s->brov_pin_ofs[i] == offset && s->brov_pin_type[i] == type) {
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

/* Only an op-stream call may leave pins held, since a stub returns to code that expects them all in registers. */
static void brov_pin_helper_call(TCGContext *s, int flags, bool from_ops)
{
    if (s->brov_pin_count == 0) {
        return;
    }
    if (flags & TCG_CALL_NO_READ_GLOBALS) {
        s->brov_pin_sync = BROV_PIN_CHOSEN | BROV_PIN_INLINE | BROV_PIN_SPILL_CALLER | BROV_PIN_RELOAD_CALLER;
    } else if (flags & TCG_CALL_NO_RETURN) {
        s->brov_pin_sync = BROV_PIN_CHOSEN | BROV_PIN_INLINE | BROV_PIN_SPILL;
    } else if (flags & TCG_CALL_NO_WRITE_GLOBALS) {
        s->brov_pin_sync = BROV_PIN_CHOSEN | BROV_PIN_INLINE | BROV_PIN_SPILL | BROV_PIN_RELOAD_CALLER;
    } else {
        s->brov_pin_sync = BROV_PIN_CHOSEN | BROV_PIN_INLINE | BROV_PIN_SPILL | BROV_PIN_RELOAD;
    }
    if (from_ops) {
        s->brov_pin_sync |= BROV_PIN_RELOAD_LAZY;
    }
}

/* A held pin is in env already, and a lazy reload adds its pins to the held set. */
static void brov_pin_sync_masks(TCGContext *s, unsigned sync, uint32_t *spill, uint32_t *reload)
{
    *spill = (sync & BROV_PIN_SPILL) ? s->brov_pin_all : (sync & BROV_PIN_SPILL_CALLER) ? s->brov_pin_caller : 0;
    *reload = (sync & BROV_PIN_RELOAD) ? s->brov_pin_all : (sync & BROV_PIN_RELOAD_CALLER) ? s->brov_pin_caller : 0;
    *spill &= ~s->brov_pin_env_held;
    *reload &= ~s->brov_pin_env_held;
    if (sync & BROV_PIN_RELOAD_LAZY) {
        s->brov_pin_env_held |= *reload & s->brov_pin_lazy_ok;
        *reload &= ~s->brov_pin_lazy_ok;
    }
}

/* The reload sits inside the call, so it comes before the caller moves a result. */
static bool brov_pin_call(TCGContext *s, tcg_insn_unit *target)
{
    unsigned sync = s->brov_pin_sync;
    void (*emit)(TCGContext *, bool, uint32_t);
    uint32_t spill, reload;

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
    brov_pin_sync_masks(s, sync, &spill, &reload);

    emit = (sync & BROV_PIN_INLINE) ? brov_pin_emit : brov_pin_emit_far;
    s->brov_pin_sync = BROV_PIN_BUSY;
    emit(s, false, spill);
    tcg_out_call(s, target);
    emit(s, true, reload);
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

static inline void brov_pin_helper_call(TCGContext *s, int flags, bool from_ops)
{
}

static inline uint32_t brov_pin_mask_of(TCGContext *s, TCGReg reg)
{
    return 0;
}

static inline void brov_pin_env_begin(TCGContext *s, uint32_t mask)
{
}

static inline void brov_pin_env_end(TCGContext *s)
{
}

static inline void brov_pin_before_op(TCGContext *s, const TCGOp *op)
{
}

#endif

#endif
