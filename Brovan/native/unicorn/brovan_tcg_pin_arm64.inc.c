#ifndef BROVAN_TCG_PIN_ARM64_INC_C
#define BROVAN_TCG_PIN_ARM64_INC_C

/* Callee-saved, so a C call that reads no guest state needs no sync. */
static const TCGReg brov_pin_host_regs[] = {
    TCG_REG_X20, TCG_REG_X21, TCG_REG_X22, TCG_REG_X23,
    TCG_REG_X24, TCG_REG_X25, TCG_REG_X26, TCG_REG_X27,
};

static void brov_pin_emit(TCGContext *s, bool load)
{
    unsigned i = 0;

    while (i < s->brov_pin_count) {
        int32_t ofs = s->brov_pin_ofs[i];

        if (i + 1 < s->brov_pin_count && s->brov_pin_ofs[i + 1] == ofs + 8 &&
            ofs >= -512 && ofs <= 504 && (ofs & 7) == 0) {
            if (load) {
                tcg_out_insn(s, 3314, LDP, s->brov_pin_reg[i], s->brov_pin_reg[i + 1], TCG_AREG0, ofs, 1, 0);
            } else {
                tcg_out_insn(s, 3314, STP, s->brov_pin_reg[i], s->brov_pin_reg[i + 1], TCG_AREG0, ofs, 1, 0);
            }
            i += 2;
        } else {
            if (load) {
                tcg_out_ld(s, TCG_TYPE_I64, s->brov_pin_reg[i], TCG_AREG0, ofs);
            } else {
                tcg_out_st(s, TCG_TYPE_I64, s->brov_pin_reg[i], TCG_AREG0, ofs);
            }
            i++;
        }
    }
}

static void brov_pin_stubs_emit(TCGContext *s)
{
    s->brov_pin_spill_stub = NULL;
    s->brov_pin_reload_stub = NULL;
    if (s->brov_pin_count == 0) {
        return;
    }

    s->brov_pin_spill_stub = s->code_ptr;
    brov_pin_emit(s, false);
    tcg_out_insn(s, 3207, RET, TCG_REG_LR);

    s->brov_pin_reload_stub = s->code_ptr;
    brov_pin_emit(s, true);
    tcg_out_insn(s, 3207, RET, TCG_REG_LR);
}

/* Every guest memory op has its own slow path, so a slow path calls the shared copy. */
static void brov_pin_emit_far(TCGContext *s, bool load)
{
    tcg_insn_unit *stub = load ? s->brov_pin_reload_stub : s->brov_pin_spill_stub;
    ptrdiff_t offset = stub - s->code_ptr;

    if (stub != NULL && offset == sextract64(offset, 0, 26)) {
        tcg_out_insn(s, 3206, BL, offset);
    } else {
        brov_pin_emit(s, load);
    }
}

#endif
