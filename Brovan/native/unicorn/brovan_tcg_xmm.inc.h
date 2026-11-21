/* After sync_xmm no XMM global is in a host register, so the next op that uses one loads it again.
 * tcg_optimize forgets what it knows about them at the same op. A pinned XMM register is in env from sync_xmm
 * to sync_xmm_end. */
#ifndef BROVAN_TCG_XMM_INC_H
#define BROVAN_TCG_XMM_INC_H

static void temp_sync(TCGContext *s, TCGTemp *ts, TCGRegSet allocated_regs,
                      TCGRegSet preferred_regs, int free_or_dead);

static void brov_xmm_liveness(TCGContext *s)
{
    int i;

    for (i = 0; i < s->brov_xmm_count; i++) {
        TCGTemp *ts = &s->temps[s->brov_xmm_first + i];

        ts->state = TS_DEAD | TS_MEM;
        la_reset_pref(s, ts);
    }
}

static void brov_xmm_alloc(TCGContext *s)
{
    uint32_t pinned = 0;
    int i;

    for (i = 0; i < s->brov_xmm_count; i++) {
        TCGTemp *ts = &s->temps[s->brov_xmm_first + i];

        if (ts->fixed_reg) {
            pinned |= brov_pin_mask_of(s, ts->reg);
        } else {
            temp_sync(s, ts, s->reserved_regs, 0, -1);
        }
    }
    brov_pin_env_begin(s, pinned);
}

/* The stock frame slot holds 8 bytes at an 8 byte boundary, but the backend spills a 128 bit temp with
 * an instruction that needs 16 bytes at a 16 byte boundary. */
static bool brov_vec_temp_slot(TCGContext *s, TCGTemp *ts)
{
    const intptr_t size = 16;
    intptr_t offset;

    if (ts->type != TCG_TYPE_V128) {
        return false;
    }

    offset = ROUND_UP(s->current_frame_offset, size);
    if (offset + size > s->frame_end) {
        tcg_abort();
    }
    ts->mem_offset = offset;
    ts->mem_base = s->frame_temp;
    ts->mem_allocated = 1;
    s->current_frame_offset = offset + size;
    return true;
}

#endif
