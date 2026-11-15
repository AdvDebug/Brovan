/* A miss, a code segment with a base, or other flags jump to helper_lookup_tb_ptr, which returns to the
 * block in the stub's place. The stub sits behind the epilogue, so a restored code cache checks it with the
 * prologue. */
#if defined(__aarch64__) && defined(TARGET_X86_64)

void *helper_lookup_tb_ptr(CPUArchState *env);

enum {
    BROV_STUB_CCMP_X2_0_EQ = 0xfa400840,
    BROV_STUB_CMP_X5_X16 = 0xeb1000bf,
    BROV_STUB_CMP_X5_X1 = 0xeb0100bf,
    BROV_STUB_EOR_X3_X1_LSR = 0xca414023,
    BROV_STUB_ADD_X3_X7_LSL = 0x8b0310e3,
    BROV_STUB_ORR_X1_X1_X6 = 0xaa060021,
    BROV_STUB_B_NE = 0x54000001,
    BROV_STUB_CBZ_X0 = 0xb4000000,
};

QEMU_BUILD_BUG_ON(BROV_JMP_HASH_SHIFT != 16);
QEMU_BUILD_BUG_ON(BROV_JMP_ENTRY_SHIFT != 4);
QEMU_BUILD_BUG_ON(offsetof(brov_jmp_entry, tc_ptr) != 0 || offsetof(brov_jmp_entry, key) != 8);
QEMU_BUILD_BUG_ON(offsetof(brov_lookup_state, flags) != 0 || offsetof(brov_lookup_state, key) != 8 ||
                  offsetof(brov_lookup_state, table) != 16);

static bool brov_lookup_stub_off(void)
{
    static int off = -1;

    if (off < 0) {
        off = getenv("BROVAN_NO_JMP_STUB") != NULL;
    }
    return off != 0;
}

/* X30 holds the return address into the block, so the helper returns there. */
static void brov_lookup_stub_tail(TCGContext *s)
{
    if (!brov_slot_emit(s, (const void *)helper_lookup_tb_ptr, false)) {
        tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_X17, (intptr_t)helper_lookup_tb_ptr);
        tcg_out_insn(s, 3207, BR, TCG_REG_X17);
    }
}

/* In: X16 holds the flags of the calling block, X19 env. Out: X0. */
static void brov_lookup_stub_emit(TCGContext *s)
{
    struct uc_struct *uc = s->uc;
    tcg_insn_unit *miss[3];
    unsigned i;

    s->brov_lookup_stub = NULL;
    if (brov_lookup_stub_off() || !brov_jmp_ensure(uc)) {
        return;
    }

    s->brov_lookup_stub = s->code_ptr;
    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_X4, (intptr_t)&uc->brov_lookup);
    tcg_out_insn(s, 3314, LDP, TCG_REG_X5, TCG_REG_X6, TCG_REG_X4, 0, 1, 0);
    tcg_out_ld(s, TCG_TYPE_I64, TCG_REG_X1, TCG_AREG0, offsetof(CPUX86State, eip));
    tcg_out_ld(s, TCG_TYPE_I64, TCG_REG_X2, TCG_AREG0, offsetof(CPUX86State, segs[R_CS].base));
    tcg_out32(s, BROV_STUB_CMP_X5_X16);
    tcg_out32(s, BROV_STUB_CCMP_X2_0_EQ);
    miss[0] = s->code_ptr;
    tcg_out32(s, BROV_STUB_B_NE);

    tcg_out_ld(s, TCG_TYPE_I64, TCG_REG_X7, TCG_REG_X4, offsetof(brov_lookup_state, table));
    tcg_out32(s, BROV_STUB_EOR_X3_X1_LSR);
    tcg_out_logicali(s, I3404_ANDI, TCG_TYPE_I64, TCG_REG_X3, TCG_REG_X3, BROV_JMP_MASK);
    tcg_out32(s, BROV_STUB_ADD_X3_X7_LSL);
    tcg_out_insn(s, 3314, LDP, TCG_REG_X0, TCG_REG_X5, TCG_REG_X3, 0, 1, 0);
    tcg_out32(s, BROV_STUB_ORR_X1_X1_X6);
    tcg_out32(s, BROV_STUB_CMP_X5_X1);
    miss[1] = s->code_ptr;
    tcg_out32(s, BROV_STUB_B_NE);
    miss[2] = s->code_ptr;
    tcg_out32(s, BROV_STUB_CBZ_X0);
    tcg_out_insn(s, 3207, RET, TCG_REG_LR);

    for (i = 0; i < ARRAY_SIZE(miss); i++) {
        reloc_pc19(miss[i], s->code_ptr);
    }
    tcg_out_mov(s, TCG_TYPE_PTR, TCG_REG_X0, TCG_AREG0);
    if (s->brov_pin_count == 0) {
        brov_lookup_stub_tail(s);
        return;
    }
    /* A call, so that a pin has a point to come back to. */
    tcg_out_insn(s, 3314, STP, TCG_REG_FP, TCG_REG_LR, TCG_REG_SP, -16, 1, 1);
    brov_pin_helper_call(s, TCG_CALL_NO_WG_SE);
    tcg_out_call(s, (tcg_insn_unit *)helper_lookup_tb_ptr);
    tcg_out_insn(s, 3314, LDP, TCG_REG_FP, TCG_REG_LR, TCG_REG_SP, 16, 0, 1);
    tcg_out_insn(s, 3207, RET, TCG_REG_LR);
}

static const TCGTargetOpDef brov_lookup_stub_r = { .args_ct_str = { "r" } };

static const TCGTargetOpDef *brov_lookup_stub_op_def(TCGOpcode op)
{
    return op == INDEX_op_lookup_tb_stub ? &brov_lookup_stub_r : NULL;
}

static bool brov_lookup_stub_out(TCGContext *s, TCGOpcode opc, const TCGArg *args)
{
    if (opc != INDEX_op_lookup_tb_stub) {
        return false;
    }

    tcg_out_movi(s, TCG_TYPE_I64, TCG_REG_X16, (uint32_t)args[1]);
    /* The stub is translated code. Its own call into C syncs the pins. */
    s->brov_pin_sync = BROV_PIN_CHOSEN;
    tcg_out_call(s, (tcg_insn_unit *)s->brov_lookup_stub);
    tcg_out_mov(s, TCG_TYPE_I64, args[0], TCG_REG_X0);
    return true;
}

#else

static void brov_lookup_stub_emit(TCGContext *s)
{
    s->brov_lookup_stub = NULL;
}

static const TCGTargetOpDef *brov_lookup_stub_op_def(TCGOpcode op)
{
    return NULL;
}

static bool brov_lookup_stub_out(TCGContext *s, TCGOpcode opc, const TCGArg *args)
{
    return false;
}

#endif
