/* Included into qemu/include/exec/gen-icount.h, just above gen_tb_start.
 *
 * Unicorn polls the exit request with a helper call at the top of every block,
 * where the condition is just a 32-bit load at a constant offset from cpu_env.
 * QEMU emits a load and a not-taken branch instead; see gen_tb_start/gen_tb_end
 * in accel/tcg/translator.c.
 *
 * The shape is load-bearing. Branching over the helper and rejoining inside the
 * block prologue splits the TCG basic block and fails liveness analysis - that is
 * what Unicorn's comment about brcondi warns about. Upstream branches *out* of
 * the block to a label emitted after its final exit, so there is no join.
 */
#ifndef BROVAN_TCG_EXITCHECK_H
#define BROVAN_TCG_EXITCHECK_H

static inline void brov_gen_exit_check_start(TCGContext *tcg_ctx, TCGv_ptr puc,
                                             TCGv_i32 delay_slot)
{
    TCGv_i32 count;

    /* Targets with delay slots pass a runtime flag the trailing block cannot see
     * once its temp is freed; leave those on the unconditional helper call. */
    if (tcg_ctx->delay_slot_flag != NULL) {
        gen_helper_check_exit_request(tcg_ctx, puc, delay_slot);
        tcg_ctx->brov_exitreq_label = NULL;
        return;
    }

    count = tcg_temp_new_i32(tcg_ctx);
    tcg_gen_ld_i32(tcg_ctx, count, tcg_ctx->cpu_env,
                   offsetof(ArchCPU, neg.icount_decr.u32) - offsetof(ArchCPU, env));
    tcg_ctx->brov_exitreq_label = gen_new_label(tcg_ctx);
    tcg_gen_brcondi_i32(tcg_ctx, TCG_COND_LT, count, 0, tcg_ctx->brov_exitreq_label);
    tcg_temp_free_i32(tcg_ctx, count);
}

/* Emitted after the block's own exit_tb, so it is only ever reached by the
 * branch above and never falls through into or out of the block body. */
static inline void brov_gen_exit_check_end(TCGContext *tcg_ctx)
{
    TCGv_ptr puc;
    TCGv_i32 zero;

    if (tcg_ctx->brov_exitreq_label == NULL) {
        return;
    }

    gen_set_label(tcg_ctx, tcg_ctx->brov_exitreq_label);
    tcg_ctx->brov_exitreq_label = NULL;

    puc = tcg_const_ptr(tcg_ctx, tcg_ctx->uc);
    zero = tcg_const_i32(tcg_ctx, 0);
    gen_helper_check_exit_request(tcg_ctx, puc, zero);
    tcg_temp_free_i32(tcg_ctx, zero);
    tcg_temp_free_ptr(tcg_ctx, puc);
}

#endif
