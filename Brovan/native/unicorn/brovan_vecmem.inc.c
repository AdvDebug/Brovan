/* BROV_MO_V128 makes the TLB probe check the last of the 16 bytes, so an access that crosses a page takes
 * the slow path. The slow path makes two 8 byte accesses, which is what hooks, faults and stores into code
 * expect. No host returns 128 bits in a register, so the value passes through env. */

#define BROV_VECMEM_IDX_BITS 8
#define BROV_VECMEM_INFO(ofs, idx) (((uint32_t)(ofs) << BROV_VECMEM_IDX_BITS) | (uint32_t)(idx))
#define BROV_VECMEM_OFS(info) ((intptr_t)((info) >> BROV_VECMEM_IDX_BITS))

static uint64_t *brov_vecmem_slot(CPUArchState *env, uint32_t info)
{
    return (uint64_t *)((uint8_t *)env + BROV_VECMEM_OFS(info));
}

static TCGMemOpIdx brov_vecmem_oi(uint32_t info)
{
    return make_memop_idx(MO_LEQ, info & ((1u << BROV_VECMEM_IDX_BITS) - 1));
}

/* Both halves are read before the slot changes, so a fault on the second half leaves the register as it was. */
static void brov_vecmem_ld_helper(CPUArchState *env, target_ulong addr,
                                  uint32_t info, uintptr_t retaddr)
{
    uint64_t *slot = brov_vecmem_slot(env, info);
    uint64_t low = helper_le_ldq_mmu(env, addr, brov_vecmem_oi(info), retaddr);
    uint64_t high = helper_le_ldq_mmu(env, addr + 8, brov_vecmem_oi(info), retaddr);

    slot[0] = low;
    slot[1] = high;
}

static void brov_vecmem_st_helper(CPUArchState *env, target_ulong addr,
                                  uint32_t info, uintptr_t retaddr)
{
    uint64_t *slot = brov_vecmem_slot(env, info);

    helper_le_stq_mmu(env, addr, slot[0], brov_vecmem_oi(info), retaddr);
    helper_le_stq_mmu(env, addr + 8, slot[1], brov_vecmem_oi(info), retaddr);
}

static bool brov_vecmem_is_ld(TCGOpcode opc, bool *is_ld)
{
    switch (opc) {
    case INDEX_op_qemu_ld_v128:
        *is_ld = true;
        return true;
    case INDEX_op_qemu_st_v128:
        *is_ld = false;
        return true;
    default:
        return false;
    }
}

static void brov_vecmem_label(TCGContext *s, bool is_ld, uint32_t info, TCGReg vec,
                              TCGReg addr, tcg_insn_unit *label_ptr)
{
    TCGLabelQemuLdst *label = new_ldst_label(s);

    label->is_ld = is_ld;
    label->oi = info;
    label->type = TCG_TYPE_V128;
    label->datalo_reg = vec;
    label->addrlo_reg = addr;
    label->raddr = s->code_ptr;
    label->label_ptr[0] = label_ptr;
}

#if defined(__aarch64__)

static void tcg_out_tlb_read(TCGContext *s, TCGReg addr_reg, MemOp opc,
                             tcg_insn_unit **label_ptr, int mem_index,
                             bool is_read);

static const TCGTargetOpDef brov_vecmem_def = { .args_ct_str = { "w", "l" } };

static bool brov_vecmem_out(TCGContext *s, TCGOpcode opc, const TCGArg *args)
{
    TCGReg vec = args[0];
    TCGReg addr = args[1];
    intptr_t ofs = args[2];
    int mem_index = args[3];
    tcg_insn_unit *label_ptr;
    tcg_insn_unit *done = NULL;
    brov_direct_points direct;
    bool is_ld;

    if (!brov_vecmem_is_ld(opc, &is_ld)) {
        return false;
    }

    if (brov_direct_may_emit(s, MO_LEQ)) {
        TCGReg site_reg = is_ld ? brov_direct_load_reg(s, TCG_TYPE_V128, vec, addr) : vec;

        brov_direct_check(s, addr, 16, is_ld, &direct);
        tcg_out_ldst_r(s, is_ld ? I3312_LDRVQ : I3312_STRVQ, site_reg, TCG_REG_X28, TCG_TYPE_I64, TCG_REG_X3);
        done = brov_direct_site_end(s, &direct);
        brov_direct_note_move(done, TCG_TYPE_V128, vec, site_reg);
    }
    tcg_out_tlb_read(s, addr, MO_LEQ | BROV_MO_V128, &label_ptr, mem_index, is_ld);
    tcg_out_ldst_r(s, is_ld ? I3312_LDRVQ : I3312_STRVQ, vec, TCG_REG_X1, TCG_TYPE_I64, addr);
    brov_vecmem_label(s, is_ld, BROV_VECMEM_INFO(ofs, mem_index), vec, addr, label_ptr);
    brov_direct_done(s, done);
    return true;
}

static bool brov_vecmem_slow_path(TCGContext *s, TCGLabelQemuLdst *lb)
{
    const int type = tcg_uc_has_hookmem(s) ? R_AARCH64_JUMP26 : R_AARCH64_CONDBR19;

    if (!patch_reloc(lb->label_ptr[0], type, (intptr_t)s->code_ptr, 0)) {
        return false;
    }

    brov_ldst_keep_emit(s, lb->brov_keep, true);
    if (!lb->is_ld) {
        tcg_out_st(s, TCG_TYPE_V128, lb->datalo_reg, TCG_AREG0, BROV_VECMEM_OFS(lb->oi));
    }
    tcg_out_mov(s, TCG_TYPE_PTR, TCG_REG_X0, TCG_AREG0);
    tcg_out_mov(s, TCG_TYPE_I64, TCG_REG_X1, lb->addrlo_reg);
    tcg_out_movi(s, TCG_TYPE_I32, TCG_REG_X2, lb->oi);
    tcg_out_adr(s, TCG_REG_X3, lb->raddr);
    tcg_out_call(s, (tcg_insn_unit *)(lb->is_ld ? brov_vecmem_ld_helper : brov_vecmem_st_helper));
    if (lb->is_ld) {
        tcg_out_ld(s, TCG_TYPE_V128, lb->datalo_reg, TCG_AREG0, BROV_VECMEM_OFS(lb->oi));
    }
    brov_ldst_keep_emit(s, lb->brov_keep, false);
    tcg_out_goto(s, lb->raddr);
    return true;
}

#else

static const TCGTargetOpDef brov_vecmem_def = { .args_ct_str = { "x", "L" } };

static bool brov_vecmem_out(TCGContext *s, TCGOpcode opc, const TCGArg *args)
{
    TCGReg vec = args[0];
    TCGReg addr = args[1];
    intptr_t ofs = args[2];
    int mem_index = args[3];
    tcg_insn_unit *label_ptr[2];
    bool is_ld;

    if (!brov_vecmem_is_ld(opc, &is_ld)) {
        return false;
    }

    tcg_out_tlb_load(s, addr, 0, mem_index, MO_LEQ | BROV_MO_V128, label_ptr,
                     is_ld ? offsetof(CPUTLBEntry, addr_read)
                           : offsetof(CPUTLBEntry, addr_write));
    tcg_out_vex_modrm_offset(s, is_ld ? OPC_MOVDQU_VxWx : OPC_MOVDQU_WxVx, vec, 0, TCG_REG_L1, 0);
    brov_vecmem_label(s, is_ld, BROV_VECMEM_INFO(ofs, mem_index), vec, addr, label_ptr[0]);
    return true;
}

/* tcg_out_tlb_load left the address in the second argument register. */
static bool brov_vecmem_slow_path(TCGContext *s, TCGLabelQemuLdst *l)
{
    tcg_patch32(l->label_ptr[0], s->code_ptr - l->label_ptr[0] - 4);

    brov_ldst_keep_emit(s, l->brov_keep, true);
    if (!l->is_ld) {
        tcg_out_st(s, TCG_TYPE_V128, l->datalo_reg, TCG_AREG0, BROV_VECMEM_OFS(l->oi));
    }
    tcg_out_mov(s, TCG_TYPE_PTR, tcg_target_call_iarg_regs[0], TCG_AREG0);
    tcg_out_movi(s, TCG_TYPE_I32, tcg_target_call_iarg_regs[2], l->oi);
    tcg_out_movi(s, TCG_TYPE_PTR, tcg_target_call_iarg_regs[3], (uintptr_t)l->raddr);
    tcg_out_call(s, (tcg_insn_unit *)(l->is_ld ? brov_vecmem_ld_helper : brov_vecmem_st_helper));
    if (l->is_ld) {
        tcg_out_ld(s, TCG_TYPE_V128, l->datalo_reg, TCG_AREG0, BROV_VECMEM_OFS(l->oi));
    }
    brov_ldst_keep_emit(s, l->brov_keep, false);
    tcg_out_jmp(s, l->raddr);
    return true;
}

#endif

static const TCGTargetOpDef *brov_vecmem_op_def(TCGOpcode op)
{
    bool is_ld;

    return brov_vecmem_is_ld(op, &is_ld) ? &brov_vecmem_def : NULL;
}
