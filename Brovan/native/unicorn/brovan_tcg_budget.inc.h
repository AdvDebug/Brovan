/* Included into qemu/accel/tcg/{cpu-exec,tcg-runtime}.c and
 * qemu/target/i386/misc_helper.c. Carries the two things Brovan adds to the
 * block dispatch path: the scheduling quantum, and the jump cache below.
 *
 * Unicorn enforces the uc_emu_start() instruction limit with a UC_HOOK_CODE
 * hook. A code hook makes target/i386/translate.c wrap *every* guest
 * instruction in a PC store, an eflags flush, a callback and a second exit
 * poll, and it forces the lazy CC_OP state to be materialised at each
 * instruction boundary - so asking for a limit at all costs several times the
 * throughput of asking for none. Brovan only ever wants a scheduling quantum,
 * which does not have to be exact, so the limit is carried as a per-block
 * decrement instead (brovan_tcg_exitcheck.inc.h) and this is where an exhausted
 * one is noticed.
 *
 * static inline: the per-target translation units are linked into one library
 * and nothing Brovan adds goes through Unicorn's per-target symbol renaming. */
#ifndef BROVAN_TCG_BUDGET_H
#define BROVAN_TCG_BUDGET_H

static inline void brov_budget_expired(struct uc_struct *uc)
{
    CPUNegativeOffsetState *neg;

    if (!uc->brov_budget_mode) {
        return;
    }

    neg = cpu_neg(uc->cpu);
    if (neg->brov_insn_budget >= 0) {
        return;
    }

    /* No limit was asked for; the counter only ran because the block decrement
     * is unconditional once the mode is on. */
    if (uc->emu_count == 0) {
        neg->brov_insn_budget = INT32_MAX;
        return;
    }

    neg->brov_insn_budget = 0;
    uc_emu_stop(uc);
}

/* Only blocks translated outside budget mode reach this. Budget mode charges the
 * pause inline in brov_gen_pause_charge. */
static inline void brov_charge_pause(CPUState *cs)
{
    if (cs->uc->brov_budget_mode) {
        cpu_neg(cs)->brov_insn_budget -= BROV_PAUSE_BUDGET_COST;
    }
}

/* The jump cache needs tb_lookup__cpu_state, so it is built only where
 * exec/tb-lookup.h has already been included. misc_helper.c takes this header
 * for the budget alone and does not include it.
 *
 * An entry is believed only while cpu->tb_jmp_cache[hash] still holds the block
 * it was built from, so every path that clears or replaces a jump cache slot
 * retires the matching entry. The flush count closes the rest: a flush frees
 * every block, and a later block can land on the freed address with the same
 * key.
 *
 * BROVAN_NO_JMP_FAST=1 is the kill switch. */
#ifdef EXEC_TB_LOOKUP_H

/* Entries are wider than a jump cache slot, so the table indexes fewer of them. */
#define BROV_JMP_BITS (TB_JMP_CACHE_BITS - 1)
#define BROV_JMP_SIZE (1 << BROV_JMP_BITS)
#define BROV_JMP_MASK (BROV_JMP_SIZE - 1)

/* brov_jmp_off keeps the decision in the hot struct: one load per lookup, not a
 * call. */
static inline bool brov_jmp_alloc(struct uc_struct *uc)
{
    static int disabled = -1;

    if (disabled < 0) {
        disabled = getenv("BROVAN_NO_JMP_FAST") != NULL;
    }
    if (disabled) {
        uc->brov_jmp_off = 1;
        return false;
    }

    uc->brov_jmp = calloc(BROV_JMP_SIZE, sizeof(brov_jmp_entry));
    if (!uc->brov_jmp) {
        uc->brov_jmp_off = 1;
        return false;
    }
    uc->brov_jmp_flush = uc->tcg_ctx->tb_ctx.tb_flush_count;
    return true;
}

static inline bool brov_lookup_tb_ptr(CPUArchState *env, void **out)
{
    CPUState *cpu = env_cpu(env);
    struct uc_struct *uc = cpu->uc;
    brov_jmp_entry *e;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags, cf_mask;
    unsigned int hash;

    if (unlikely(!uc->brov_jmp) && (uc->brov_jmp_off || !brov_jmp_alloc(uc))) {
        return false;
    }

    if (unlikely(uc->brov_jmp_flush != uc->tcg_ctx->tb_ctx.tb_flush_count)) {
        memset(uc->brov_jmp, 0, BROV_JMP_SIZE * sizeof(brov_jmp_entry));
        uc->brov_jmp_flush = uc->tcg_ctx->tb_ctx.tb_flush_count;
    }

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    hash = tb_jmp_cache_hash_func(uc, pc);
    e = &uc->brov_jmp[hash & BROV_JMP_MASK];

    cf_mask = curr_cflags() & ~CF_CLUSTER_MASK;
    cf_mask |= ((uint32_t)cpu->cluster_index) << CF_CLUSTER_SHIFT;

    /* cs_base and the trace state are not in the entry, so anything but a flat
     * code segment with tracing off takes the ordinary path. */
    if (likely(e->tb == (const void *)cpu->tb_jmp_cache[hash] && e->tb != NULL &&
               e->pc == (uint64_t)pc && e->flags == flags && e->cf_mask == cf_mask &&
               cs_base == 0 && *cpu->trace_dstate == 0)) {
        *out = (void *)e->tc_ptr;
        return true;
    }

    tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, cf_mask);
    if (tb == NULL) {
        *out = uc->tcg_ctx->code_gen_epilogue;
        return true;
    }

    if (cs_base == 0 && *cpu->trace_dstate == 0) {
        e->tb = tb;
        e->tc_ptr = tb->tc.ptr;
        e->pc = (uint64_t)pc;
        e->flags = flags;
        e->cf_mask = cf_mask;
    }

    *out = tb->tc.ptr;
    return true;
}

#endif /* EXEC_TB_LOOKUP_H */

#endif
