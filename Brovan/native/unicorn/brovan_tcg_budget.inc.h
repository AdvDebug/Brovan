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
 * The entry carries the whole key, so it answers without reading
 * cpu->tb_jmp_cache. Every site that retires a jump cache slot has to retire
 * this one too: cpu_tb_jmp_cache_clear, the single slot clear in
 * tb_phys_invalidate and tb_jmp_cache_clear_page. An insert needs no hook,
 * because it only means another pc took that slot. The flush count closes the
 * rest, because a flush frees every block and a later block can land on the
 * freed address with the same key.
 *
 * BROVAN_NO_JMP_FAST=1 is the kill switch. */
#ifdef EXEC_TB_LOOKUP_H

static inline bool brov_lookup_tb_ptr(CPUArchState *env, void **out)
{
    CPUState *cpu = env_cpu(env);
    struct uc_struct *uc = cpu->uc;
    brov_jmp_entry *e;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags, cf_mask;
    unsigned id;

    if (unlikely(!uc->brov_jmp) && !brov_jmp_ensure(uc)) {
        return false;
    }

    if (unlikely(uc->brov_jmp_flush != uc->tcg_ctx->tb_ctx.tb_flush_count)) {
        memset(uc->brov_jmp, 0, BROV_JMP_SIZE * sizeof(brov_jmp_entry));
        uc->brov_jmp_flush = uc->tcg_ctx->tb_ctx.tb_flush_count;
    }

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    e = &uc->brov_jmp[brov_jmp_slot((uint64_t)pc)];

    cf_mask = curr_cflags() & ~CF_CLUSTER_MASK;
    cf_mask |= ((uint32_t)cpu->cluster_index) << CF_CLUSTER_SHIFT;
    id = brov_flagkey(uc, flags, cf_mask);

    /* cs_base and the trace state are not in the key, so anything but a flat
     * code segment with tracing off takes the ordinary path. */
    if (likely(id != 0 && e->tc_ptr != NULL &&
               e->key == brov_jmp_key((uint64_t)pc, id) &&
               cs_base == 0 && *cpu->trace_dstate == 0)) {
        *out = (void *)e->tc_ptr;
        return true;
    }

    tb = tb_lookup__cpu_state(cpu, &pc, &cs_base, &flags, cf_mask);
    if (tb == NULL) {
        *out = uc->tcg_ctx->code_gen_epilogue;
        return true;
    }

    if (cs_base == 0 && *cpu->trace_dstate == 0 && id != 0) {
        e->tc_ptr = tb->tc.ptr;
        e->key = brov_jmp_key((uint64_t)pc, id);
    }

    *out = tb->tc.ptr;
    return true;
}

#endif /* EXEC_TB_LOOKUP_H */

#endif
