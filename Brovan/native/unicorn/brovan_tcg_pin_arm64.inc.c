#ifndef BROVAN_TCG_PIN_ARM64_INC_C
#define BROVAN_TCG_PIN_ARM64_INC_C

/* x20 to x27 survive a C call, so a call that reads no guest state leaves them alone. x8 to x15 and v16 to v23 do
 * not, and no emitter uses them as a fixed scratch. */
static const brov_pin_host_reg brov_pin_host_regs[] = {
    { TCG_REG_X20, false }, { TCG_REG_X21, false }, { TCG_REG_X22, false }, { TCG_REG_X23, false },
    { TCG_REG_X24, false }, { TCG_REG_X25, false }, { TCG_REG_X26, false }, { TCG_REG_X27, false },
    { TCG_REG_X8, true },   { TCG_REG_X9, true },   { TCG_REG_X10, true },  { TCG_REG_X11, true },
    { TCG_REG_X12, true },  { TCG_REG_X13, true },  { TCG_REG_X14, true },  { TCG_REG_X15, true },
    { TCG_REG_V16, true },  { TCG_REG_V17, true },  { TCG_REG_V18, true },  { TCG_REG_V19, true },
    { TCG_REG_V20, true },  { TCG_REG_V21, true },  { TCG_REG_V22, true },  { TCG_REG_V23, true },
};

static void brov_pin_emit(TCGContext *s, bool load, uint32_t mask)
{
    mask &= s->brov_pin_all;
    while (mask != 0) {
        unsigned i = ctz32(mask);
        unsigned next;
        int32_t ofs = s->brov_pin_ofs[i];
        TCGType type = s->brov_pin_type[i];

        mask &= mask - 1;
        next = mask != 0 ? ctz32(mask) : i;
        if (next != i && type == TCG_TYPE_I64 && s->brov_pin_type[next] == TCG_TYPE_I64 &&
            s->brov_pin_ofs[next] == ofs + 8 && ofs >= -512 && ofs <= 504 && (ofs & 7) == 0) {
            if (load) {
                tcg_out_insn(s, 3314, LDP, s->brov_pin_reg[i], s->brov_pin_reg[next], TCG_AREG0, ofs, 1, 0);
            } else {
                tcg_out_insn(s, 3314, STP, s->brov_pin_reg[i], s->brov_pin_reg[next], TCG_AREG0, ofs, 1, 0);
            }
            mask &= mask - 1;
        } else if (load) {
            tcg_out_ld(s, type, s->brov_pin_reg[i], TCG_AREG0, ofs);
        } else {
            tcg_out_st(s, type, s->brov_pin_reg[i], TCG_AREG0, ofs);
        }
    }
}

/* tcg_out_ld and tcg_out_st go through x30 for an offset outside the immediate forms, and a stub returns by x30. */
static bool brov_pin_stub_reachable(TCGContext *s)
{
    unsigned i;

    for (i = 0; i < s->brov_pin_count; i++) {
        int32_t ofs = s->brov_pin_ofs[i];
        TCGType type = s->brov_pin_type[i];
        int size = type == TCG_TYPE_I32 ? 4 : type == TCG_TYPE_V128 ? 16 : 8;

        if (!(ofs >= -256 && ofs < 256) && !(ofs >= 0 && ofs % size == 0 && ofs / size <= 0xfff)) {
            return false;
        }
    }
    return true;
}

static void brov_pin_stubs_emit(TCGContext *s)
{
    memset(s->brov_pin_stub, 0, sizeof(s->brov_pin_stub));
    if (s->brov_pin_count == 0 || !brov_pin_stub_reachable(s)) {
        return;
    }
    s->brov_pin_stub[0] = s->code_ptr;
    brov_pin_emit(s, false, s->brov_pin_all);
    tcg_out_insn(s, 3207, RET, TCG_REG_LR);

    s->brov_pin_stub[1] = s->code_ptr;
    brov_pin_emit(s, true, s->brov_pin_all);
    tcg_out_insn(s, 3207, RET, TCG_REG_LR);
}

/* Every guest memory op has its own slow path, so a slow path calls the shared copy. */
static void brov_pin_emit_far(TCGContext *s, bool load, uint32_t mask)
{
    tcg_insn_unit *stub = mask == s->brov_pin_all ? s->brov_pin_stub[load] : NULL;
    ptrdiff_t offset = stub - s->code_ptr;

    if (stub != NULL && offset == sextract64(offset, 0, 26)) {
        tcg_out_insn(s, 3206, BL, offset);
    } else {
        brov_pin_emit(s, load, mask);
    }
}

#endif
