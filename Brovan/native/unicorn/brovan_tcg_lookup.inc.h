/* Inline probe of the same block lookup table the helper uses. A hit branches
 * to the block with no call, a miss falls through to the helper.
 *
 * gen_helper_lookup_tb_ptr is TCG_CALL_NO_WG, so tcg_reg_alloc_call syncs every
 * dirty guest register to env before the branch. That runs on every return and
 * every indirect call and costs more than the lookup.
 *
 * The probe compares the flags of the block being translated, and the helper
 * fills an entry with the flags that were live when it ran. Differing flags
 * give differing keys, so the probe misses rather than taking a block
 * translated under other flags.
 *
 * TCG_TARGET_HAS_brov_inlinejmp marks a host where dropping the call is worth
 * the probe. A backend that does not answer keeps the helper.
 *
 * BROVAN_NO_JMP_INLINE=1 is the kill switch. */
#ifndef TCG_TARGET_HAS_brov_inlinejmp
#define TCG_TARGET_HAS_brov_inlinejmp 0
#endif
#ifndef BROVAN_TCG_LOOKUP_INC_H
#define BROVAN_TCG_LOOKUP_INC_H

static bool brov_jmp_inline_off(void)
{
    static int off = -1;

    if (off < 0) {
        off = getenv("BROVAN_NO_JMP_INLINE") != NULL;
    }
    return off != 0;
}

static void brov_gen_lookup_inline(DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    struct uc_struct *uc = s->uc;
    brov_jmp_entry *table;
    TCGv_i64 pc, tmp, key;
    TCGv_ptr ent;
    TCGLabel *miss;
    uint32_t cf_mask;
    unsigned id;

    if (!TCG_TARGET_HAS_brov_inlinejmp || brov_jmp_inline_off()) {
        tcg_gen_lookup_and_goto_ptr(tcg_ctx);
        return;
    }

    table = brov_jmp_ensure(uc);
    if (!table) {
        tcg_gen_lookup_and_goto_ptr(tcg_ctx);
        return;
    }

    cf_mask = curr_cflags() & ~CF_CLUSTER_MASK;
    cf_mask |= ((uint32_t)uc->cpu->cluster_index) << CF_CLUSTER_SHIFT;
    id = brov_flagkey(uc, s->base.tb->flags, cf_mask);
    if (id == 0) {
        tcg_gen_lookup_and_goto_ptr(tcg_ctx);
        return;
    }

    miss = gen_new_label(tcg_ctx);
    /* brcond is TCG_OPF_BB_END, so an ordinary temp is dead after a branch. */
    pc = tcg_temp_local_new_i64(tcg_ctx);
    tmp = tcg_temp_local_new_i64(tcg_ctx);
    key = tcg_temp_local_new_i64(tcg_ctx);
    ent = tcg_temp_local_new_ptr(tcg_ctx);

    /* A non-flat code segment means eip is not the guest pc. */
    tcg_gen_ld_i64(tcg_ctx, tmp, tcg_ctx->cpu_env,
                   offsetof(CPUX86State, segs[R_CS].base));
    tcg_gen_brcondi_i64(tcg_ctx, TCG_COND_NE, tmp, 0, miss);

    tcg_gen_ld_i64(tcg_ctx, pc, tcg_ctx->cpu_env, offsetof(CPUX86State, eip));

    tcg_gen_shri_i64(tcg_ctx, tmp, pc, BROV_JMP_HASH_SHIFT);
    tcg_gen_xor_i64(tcg_ctx, tmp, tmp, pc);
    tcg_gen_andi_i64(tcg_ctx, tmp, tmp, BROV_JMP_MASK);
    tcg_gen_shli_i64(tcg_ctx, tmp, tmp, BROV_JMP_ENTRY_SHIFT);
    tcg_gen_addi_i64(tcg_ctx, tmp, tmp, (intptr_t)table);
    tcg_gen_trunc_i64_ptr(tcg_ctx, ent, tmp);

    tcg_gen_ld_i64(tcg_ctx, key, ent, offsetof(brov_jmp_entry, key));
    tcg_gen_ori_i64(tcg_ctx, tmp, pc, (uint64_t)id << BROV_JMP_ID_SHIFT);
    tcg_gen_brcond_i64(tcg_ctx, TCG_COND_NE, key, tmp, miss);

    tcg_gen_ld_i64(tcg_ctx, key, ent, offsetof(brov_jmp_entry, tc_ptr));
    tcg_gen_trunc_i64_ptr(tcg_ctx, ent, key);
    tcg_gen_op1i(tcg_ctx, INDEX_op_goto_ptr, tcgv_ptr_arg(tcg_ctx, ent));

    gen_set_label(tcg_ctx, miss);
    tcg_temp_free_ptr(tcg_ctx, ent);
    tcg_temp_free_i64(tcg_ctx, key);
    tcg_temp_free_i64(tcg_ctx, tmp);
    tcg_temp_free_i64(tcg_ctx, pc);

    tcg_gen_lookup_and_goto_ptr(tcg_ctx);
}

#endif
