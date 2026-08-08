/* Included into qemu/tcg/{i386,aarch64}/tcg-target.inc.c immediately above
 * tcg_out_call, which early-returns through it.
 *
 * Helper addresses are the one class of baked-in host pointer that cannot be
 * pinned: they move with the library's load address. Routing every reference
 * through an indirect slot lets a reloaded code cache be repointed by rewriting
 * the slot table, which is stored as offsets from an anchor inside our own
 * image. Targets that already live inside the reservation are left alone: their
 * encodings are relative and stay self-consistent. */

static bool brov_in_reservation(TCGContext *s, const void *p)
{
    const uint8_t *low = (const uint8_t *)s->brov_slots;
    const uint8_t *high = (const uint8_t *)s->initial_buffer + s->initial_buffer_size;

    return (const uint8_t *)p >= low && (const uint8_t *)p < high;
}

static bool brov_slot_emit(TCGContext *s, const void *dest, bool is_call)
{
    uint32_t idx;
    uintptr_t slot;

    if (!s->brov_slots || brov_in_reservation(s, dest)) {
        return false;
    }

    idx = brov_slot_intern(s->brov_slots, s->brov_slot_map, s->brov_slot_map_mask,
                           &s->brov_slots_used, s->brov_slot_count, dest);
    if (idx == (uint32_t)-1) {
        /* Falling back to a direct branch bakes an unrelocatable address, so the
         * session can still run but must not be saved. */
        s->brov_slots_overflowed = 1;
        return false;
    }

    slot = (uintptr_t)&s->brov_slots[idx];

#if defined(__aarch64__)
    {
        intptr_t pc = (intptr_t)s->code_ptr;
        intptr_t page_delta = ((intptr_t)slot & ~(intptr_t)0xfff) - (pc & ~(intptr_t)0xfff);
        intptr_t imm = page_delta >> 12;
        uint32_t immlo, immhi;

        if (!is_call || imm != sextract64(imm, 0, 21)) {
            s->brov_slots_overflowed = 1;
            return false;
        }
        immlo = (uint32_t)(imm & 3);
        immhi = (uint32_t)((imm >> 2) & 0x7ffff);

        /* ADRP TMP, page(slot) ; LDR TMP, [TMP, #off] ; BLR TMP */
        tcg_out32(s, 0x90000000u | (immlo << 29) | (immhi << 5) | (uint32_t)TCG_REG_TMP);
        tcg_out32(s, 0xf9400000u | ((uint32_t)((slot & 0xfff) >> 3) << 10) |
                         ((uint32_t)TCG_REG_TMP << 5) | (uint32_t)TCG_REG_TMP);
        tcg_out32(s, 0xd63f0000u | ((uint32_t)TCG_REG_TMP << 5));
    }
#elif TCG_TARGET_REG_BITS == 64
    {
        intptr_t disp = (intptr_t)slot - ((intptr_t)s->code_ptr + 6);

        if (disp != (int32_t)disp) {
            s->brov_slots_overflowed = 1;
            return false;
        }
        /* call/jmp qword ptr [rip + disp32] */
        tcg_out8(s, 0xff);
        tcg_out8(s, is_call ? 0x15 : 0x25);
        tcg_out32(s, (int32_t)disp);
    }
#else
    /* call/jmp dword ptr [slot] */
    tcg_out8(s, 0xff);
    tcg_out8(s, is_call ? 0x15 : 0x25);
    tcg_out32(s, (int32_t)(intptr_t)slot);
#endif

    return true;
}

static bool brov_tcg_out_call_slot(TCGContext *s, const void *dest)
{
    return brov_slot_emit(s, dest, true);
}

#if !defined(__aarch64__)
/* The i386 backend tail-jumps into qemu_st_helpers rather than calling it, so
 * the jump needs the same treatment as a call. */
static bool brov_tcg_out_jmp_slot(TCGContext *s, const void *dest)
{
    return brov_slot_emit(s, dest, false);
}
#endif
