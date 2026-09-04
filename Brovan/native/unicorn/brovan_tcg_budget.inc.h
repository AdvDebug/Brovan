/* Included into qemu/accel/tcg/{cpu-exec,tcg-runtime}.c, wherever a block has
 * just branched out to the exit path.
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

#endif
