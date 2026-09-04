/* Included into qemu/include/exec/gen-icount.h, just above gen_tb_start.
 *
 * Unicorn polls the exit request with a helper call at the top of every block,
 * where the condition is just a 32-bit load at a constant offset from cpu_env.
 * QEMU emits a load and a not-taken branch instead; see gen_tb_start/gen_tb_end
 * in accel/tcg/translator.c.
 *
 * The shape is load-bearing, in two ways.
 *
 * Branching over the helper and rejoining inside the block prologue splits the
 * TCG basic block and fails liveness analysis - that is what Unicorn's comment
 * about brcondi warns about. Upstream branches *out* of the block instead.
 *
 * And the branch target must be the block's trailing exit_tb, not a helper call
 * placed after it. cpu_restore_state() maps a host address back to a guest PC
 * through the block's insn-boundary table, which stops at the last guest
 * instruction; a call site past that resolves to nothing and leaves env->eip
 * holding whatever the last *unchained* block wrote - x86's gen_goto_tb stores
 * eip after the goto_tb, so a chained predecessor never wrote it at all. Exiting
 * with TB_EXIT_REQUESTED instead lets cpu_tb_exec() put the PC back from
 * tb->pc, which is what its !HOOK_EXISTS(UC_HOOK_CODE) branch exists for.
 *
 * The same branch also carries the instruction budget that replaces Unicorn's
 * per-instruction count hook; see brovan_tcg_budget.inc.h.
 */
#ifndef BROVAN_TCG_EXITCHECK_H
#define BROVAN_TCG_EXITCHECK_H

#define BROV_BUDGET_OFF \
    (offsetof(ArchCPU, neg.brov_insn_budget) - offsetof(ArchCPU, env))

/* Patched to the real block length by brov_gen_exit_check_end, which is the
 * first point at which it is known. Any value that survives to execution is a
 * bug, so it is one that stands out in a disassembly. */
#define BROV_BUDGET_INSNS_PLACEHOLDER 0xdeadbeef

/* PAUSE is a hint, so budget mode only charges the budget and the block goes on.
 * The entry check of the next block ends a slice that spent it. */
static inline void brov_gen_pause_charge(TCGContext *tcg_ctx)
{
    TCGv_i32 budget = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_ld_i32(tcg_ctx, budget, tcg_ctx->cpu_env, BROV_BUDGET_OFF);
    tcg_gen_subi_i32(tcg_ctx, budget, budget, BROV_PAUSE_BUDGET_COST);
    tcg_gen_st_i32(tcg_ctx, budget, tcg_ctx->cpu_env, BROV_BUDGET_OFF);
    tcg_temp_free_i32(tcg_ctx, budget);
}

static inline void brov_gen_budget(TCGContext *tcg_ctx, TCGv_i32 exitreq)
{
    TCGv_i32 budget = tcg_temp_new_i32(tcg_ctx);
    TCGv_i32 insns = tcg_temp_new_i32(tcg_ctx);

    tcg_gen_ld_i32(tcg_ctx, budget, tcg_ctx->cpu_env, BROV_BUDGET_OFF);
    tcg_gen_movi_i32(tcg_ctx, insns, BROV_BUDGET_INSNS_PLACEHOLDER);
    tcg_ctx->brov_budget_insns = tcg_last_op(tcg_ctx);
    tcg_gen_sub_i32(tcg_ctx, budget, budget, insns);
    tcg_temp_free_i32(tcg_ctx, insns);

    /* Stored before the branch rather than after it, so the value does not have
     * to survive a basic-block boundary in a plain temp. The cost is that a
     * block which exits without running is still charged for; over a scheduling
     * quantum of hundreds of thousands of instructions that is noise. */
    tcg_gen_st_i32(tcg_ctx, budget, tcg_ctx->cpu_env, BROV_BUDGET_OFF);

    /* Either condition is "negative", so one branch tests both. */
    if (exitreq != NULL) {
        tcg_gen_or_i32(tcg_ctx, exitreq, exitreq, budget);
    }
    tcg_temp_free_i32(tcg_ctx, budget);
}

static inline void brov_gen_exit_check_start(TCGContext *tcg_ctx, TCGv_ptr puc,
                                             TCGv_i32 delay_slot)
{
    TCGv_i32 count;

    tcg_ctx->brov_budget_insns = NULL;

    /* Targets with delay slots pass a runtime flag the trailing block cannot see
     * once its temp is freed; leave those on the unconditional helper call, which
     * notices an exhausted budget on its own. */
    if (tcg_ctx->delay_slot_flag != NULL) {
        if (tcg_ctx->uc->brov_budget_mode) {
            brov_gen_budget(tcg_ctx, NULL);
        }
        gen_helper_check_exit_request(tcg_ctx, puc, delay_slot);
        tcg_ctx->brov_exitreq_label = NULL;
        return;
    }

    count = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_ld_i32(tcg_ctx, count, tcg_ctx->cpu_env,
                   offsetof(ArchCPU, neg.icount_decr.u32) - offsetof(ArchCPU, env));

    if (tcg_ctx->uc->brov_budget_mode) {
        brov_gen_budget(tcg_ctx, count);
    }

    tcg_ctx->brov_exitreq_label = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_LT, count, 0, tcg_ctx->brov_exitreq_label);
    tcg_temp_free_i32(tcg_ctx, count);
}

/* Called from gen_tb_end immediately before the trailing exit_tb that Unicorn
 * already emits, so that exit becomes the branch target. */
static inline void brov_gen_exit_check_end(TCGContext *tcg_ctx, int num_insns)
{
    if (tcg_ctx->brov_budget_insns != NULL) {
        tcg_set_insn_param(tcg_ctx->brov_budget_insns, 1, num_insns);
        tcg_ctx->brov_budget_insns = NULL;
    }

    if (tcg_ctx->brov_exitreq_label == NULL) {
        return;
    }

    gen_set_label(tcg_ctx, tcg_ctx->brov_exitreq_label);
    tcg_ctx->brov_exitreq_label = NULL;
}

#endif
