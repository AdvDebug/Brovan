/* Included into tcg/aarch64/tcg-target.inc.c. The direct guest memory access of an x86 guest:
 *
 *   [store wider than a byte]  and x2, addr, #0xfff; cmp x2, #(4096 - size); b.hi probe
 *   and x3, addr, #(W - 1); cmp x3, addr; b.ne probe
 *   one access with base x28 and offset x3     the site
 *   b done
 *   probe: the TLB access, whose slow path label returns to done
 *
 * The fault handler resumes at site + 8, so every guest memory op must emit exactly this shape.
 * The masked offset keeps even a mispredicted access inside the window.
 * A load that faults leaves its destination undefined, so a load into its own address register goes through x2.
 * A store that may cross a page takes the probe, because x86 writes neither page when the second one faults. */

typedef struct {
    tcg_insn_unit *cross;
    tcg_insn_unit *outside;
    tcg_insn_unit *site;
} brov_direct_points;

#if BROV_HOST_HAS_DIRECT_EMITTER && defined(TARGET_I386)

#define BROV_WINDOW_ENV_OFS ((int)offsetof(ArchCPU, neg.brov_window_base) - (int)offsetof(ArchCPU, env))

static void tcg_out_qemu_ld_direct(TCGContext *s, MemOp memop, TCGType ext, TCGReg data_r, TCGReg addr_r,
                                   TCGType otype, TCGReg off_r);
static void tcg_out_qemu_st_direct(TCGContext *s, MemOp memop, TCGReg data_r, TCGReg addr_r, TCGType otype,
                                   TCGReg off_r);

static void brov_direct_reserve(TCGContext *s)
{
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_X28);
}

static void brov_direct_prologue(TCGContext *s)
{
    tcg_out_ld(s, TCG_TYPE_PTR, TCG_REG_X28, TCG_AREG0, BROV_WINDOW_ENV_OFS);
}

/* A byte swap adds an instruction to the access, and an alignment check must fault. */
static bool brov_direct_may_emit(TCGContext *s, MemOp memop)
{
    return brov_window_emit_mask() != 0 && !tcg_uc_has_hookmem(s) && TARGET_LONG_BITS == 64 &&
           (memop & MO_BSWAP) == 0 && get_alignment_bits(memop) == 0;
}

static struct {
    tcg_insn_unit *done;
    TCGType type;
    TCGReg data_reg;
} brov_direct_move;

static void brov_direct_check(TCGContext *s, TCGReg addr_reg, unsigned size, bool is_ld, brov_direct_points *p)
{
    p->cross = NULL;
    if (!is_ld && size > 1) {
        tcg_out_logicali(s, I3404_ANDI, 1, TCG_REG_X2, addr_reg, 0xfff);
        tcg_out_cmp(s, 1, TCG_REG_X2, 4096 - size, 1);
        p->cross = s->code_ptr;
        tcg_out_insn(s, 3202, B_C, TCG_COND_GTU, 0);
    }
    tcg_out_logicali(s, I3404_ANDI, 1, TCG_REG_X3, addr_reg, brov_window_emit_mask());
    tcg_out_cmp(s, 1, TCG_REG_X3, addr_reg, 0);
    p->outside = s->code_ptr;
    tcg_out_insn(s, 3202, B_C, TCG_COND_NE, 0);
    p->site = s->code_ptr;
    brov_window_note_site();
}

static tcg_insn_unit *brov_direct_site_end(TCGContext *s, const brov_direct_points *p)
{
    tcg_insn_unit *done;

    tcg_debug_assert(s->code_ptr == p->site + 1);
    done = s->code_ptr;
    tcg_out_insn(s, 3206, B, 0);
    if (p->cross) {
        reloc_pc19(p->cross, s->code_ptr);
    }
    reloc_pc19(p->outside, s->code_ptr);
    return done;
}

static void brov_direct_done(TCGContext *s, tcg_insn_unit *done)
{
    tcg_insn_unit *skip;

    if (!done) {
        return;
    }
    if (brov_direct_move.done != done) {
        reloc_pc26(done, s->code_ptr);
        return;
    }
    skip = s->code_ptr;
    tcg_out_insn(s, 3206, B, 0);
    reloc_pc26(done, s->code_ptr);
    tcg_out_mov(s, brov_direct_move.type, brov_direct_move.data_reg, TCG_REG_X2);
    reloc_pc26(skip, s->code_ptr);
    brov_direct_move.done = NULL;
}

static tcg_insn_unit *brov_direct_emit(TCGContext *s, MemOp memop, TCGType ext, TCGReg data_reg, TCGReg addr_reg,
                                       bool is_ld)
{
    brov_direct_points p;
    bool moved = is_ld && data_reg == addr_reg;
    tcg_insn_unit *done;

    if (!brov_direct_may_emit(s, memop)) {
        return NULL;
    }
    brov_direct_check(s, addr_reg, 1u << (memop & MO_SIZE), is_ld, &p);
    if (is_ld) {
        tcg_out_qemu_ld_direct(s, memop, ext, moved ? TCG_REG_X2 : data_reg, TCG_REG_X28, TCG_TYPE_I64, TCG_REG_X3);
    } else {
        tcg_out_qemu_st_direct(s, memop, data_reg, TCG_REG_X28, TCG_TYPE_I64, TCG_REG_X3);
    }
    done = brov_direct_site_end(s, &p);
    brov_direct_move.done = moved ? done : NULL;
    brov_direct_move.type = ext;
    brov_direct_move.data_reg = data_reg;
    return done;
}

#else

static void brov_direct_reserve(TCGContext *s)
{
    (void)s;
}

static bool brov_direct_may_emit(TCGContext *s, MemOp memop)
{
    (void)s;
    (void)memop;
    return false;
}

static void brov_direct_check(TCGContext *s, TCGReg addr_reg, unsigned size, bool is_ld, brov_direct_points *p)
{
    (void)s;
    (void)addr_reg;
    (void)size;
    (void)is_ld;
    p->cross = p->outside = p->site = NULL;
}

static tcg_insn_unit *brov_direct_site_end(TCGContext *s, const brov_direct_points *p)
{
    (void)s;
    (void)p;
    return NULL;
}

static void brov_direct_prologue(TCGContext *s)
{
    (void)s;
}

static tcg_insn_unit *brov_direct_emit(TCGContext *s, MemOp memop, TCGType ext, TCGReg data_reg, TCGReg addr_reg,
                                       bool is_ld)
{
    (void)s;
    (void)memop;
    (void)ext;
    (void)data_reg;
    (void)addr_reg;
    (void)is_ld;
    return NULL;
}

static void brov_direct_done(TCGContext *s, tcg_insn_unit *done)
{
    (void)s;
    (void)done;
}

#endif
