/* The XMM registers are TCG globals, but gen_sse still reaches them through env.
 * A path claims an instruction (brov_xmm_claim) after its last check, and then
 * makes every XMM access of that instruction through brov_xmm_open. Any other
 * instruction gets sync_xmm in front of it, and env owns the registers until it
 * ends.
 *
 * The host FPU has its own rounding and denormal handling, so the arithmetic
 * and the conversions run only under HF_BROV_FPN_MASK. A NaN operand still
 * propagates by the host rule for which operand wins. */
#ifndef BROVAN_FP_VEC_INC_H
#define BROVAN_FP_VEC_INC_H

static void gen_sse(CPUX86State *env, DisasContext *s, int b,
                    target_ulong pc_start, int rex_r);

static bool brov_fp_vec_off(void)
{
    return brov_switch_set(BROV_SWITCH_NO_FPVEC);
}

static void brov_gen_mxcsr_eob(DisasContext *s)
{
    gen_jmp_im(s, s->pc - s->cs_base);
    gen_eob(s);
}

static void brov_xmm_init(struct uc_struct *uc)
{
    static const char names[BROV_XMM_MAX][6] = {
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    };
    TCGContext *tcg_ctx = uc->tcg_ctx;
    bool pinned = false;
    int i;

    tcg_ctx->brov_xmm_count = 0;
    if (!TCG_TARGET_HAS_v128 || !tcg_ctx->brov_xmm_on) {
        return;
    }
    for (i = 0; i < BROV_XMM_MAX; i++) {
        TCGTemp *ts = tcg_global_mem_new_internal(tcg_ctx, TCG_TYPE_V128, tcg_ctx->cpu_env,
                                                  offsetof(CPUX86State, xmm_regs[i]), names[i]);

        if (i == 0) {
            tcg_ctx->brov_xmm_first = (uint16_t)temp_idx(tcg_ctx, ts);
        }
        pinned |= ts->fixed_reg;
        /* sync_xmm takes them as one range of temps, and a pinned XMM register has no other sync. */
        if (temp_idx(tcg_ctx, ts) != (size_t)tcg_ctx->brov_xmm_first + i) {
            if (pinned) {
                tcg_abort();
            }
            return;
        }
        tcg_ctx->brov_xmm[i] = temp_tcgv_vec(tcg_ctx, ts);
    }
    tcg_ctx->brov_xmm_count = BROV_XMM_MAX;
}

static void brov_xmm_claim(DisasContext *s)
{
    s->brov_xmm_claimed = true;
}

/* A claimed instruction must not reach an XMM register through env, directly or
 * from a helper. An access through a pointer computed from env escapes this check. */
static void brov_xmm_check_claim(TCGContext *tcg_ctx, TCGOp *before)
{
    const TCGArg env = tcgv_ptr_arg(tcg_ctx, tcg_ctx->cpu_env);
    const TCGArg first = offsetof(CPUX86State, xmm_regs[0]);
    const TCGArg end = offsetof(CPUX86State, xmm_regs[BROV_XMM_MAX]);
    TCGOp *op;

    for (op = QTAILQ_NEXT(before, link); op != NULL; op = QTAILQ_NEXT(op, link)) {
        switch (op->opc) {
        case INDEX_op_call:
            if (op->args[TCGOP_CALLO(op) + TCGOP_CALLI(op) + 1] &
                (TCG_CALL_NO_READ_GLOBALS | TCG_CALL_NO_WRITE_GLOBALS)) {
                tcg_abort();
            }
            break;
        case INDEX_op_ld8u_i32:
        case INDEX_op_ld8s_i32:
        case INDEX_op_ld16u_i32:
        case INDEX_op_ld16s_i32:
        case INDEX_op_ld_i32:
        case INDEX_op_st8_i32:
        case INDEX_op_st16_i32:
        case INDEX_op_st_i32:
        case INDEX_op_ld8u_i64:
        case INDEX_op_ld8s_i64:
        case INDEX_op_ld16u_i64:
        case INDEX_op_ld16s_i64:
        case INDEX_op_ld32u_i64:
        case INDEX_op_ld32s_i64:
        case INDEX_op_ld_i64:
        case INDEX_op_st8_i64:
        case INDEX_op_st16_i64:
        case INDEX_op_st32_i64:
        case INDEX_op_st_i64:
        case INDEX_op_ld_vec:
        case INDEX_op_st_vec:
        case INDEX_op_dupm_vec:
        case INDEX_op_ld32_vec:
            if (op->args[1] == env && op->args[2] >= first && op->args[2] < end) {
                tcg_abort();
            }
            break;
        case INDEX_op_qemu_ld_v128:
        case INDEX_op_qemu_st_v128:
            if (op->args[2] >= first && op->args[2] < end) {
                tcg_abort();
            }
            break;
        default:
            break;
        }
    }
}

static bool brov_op_writes(TCGContext *tcg_ctx, const TCGOp *op, TCGArg arg)
{
    int nb_oargs = op->opc == INDEX_op_call ? TCGOP_CALLO(op) : tcg_ctx->tcg_op_defs[op->opc].nb_oargs;
    int i;

    for (i = 0; i < nb_oargs; i++) {
        if (op->args[i] == arg) {
            return true;
        }
    }
    return false;
}

static bool brov_t0_forward(TCGContext *tcg_ctx, TCGOp *store, TCGOp *load)
{
    TCGOpcode opc;
    unsigned type, vece;
    TCGOp *mov;

    if (store->opc == INDEX_op_st_vec && load->opc == INDEX_op_ld_vec && TCGOP_VECL(store) == 1 &&
        TCGOP_VECL(load) == 1) {
        opc = INDEX_op_mov_vec;
        type = 1;
        vece = 0;
    } else if (store->opc == INDEX_op_st32_i64 && load->opc == INDEX_op_ld32_vec) {
        opc = INDEX_op_movi2v_vec;
        type = 0;
        vece = MO_32;
    } else if (store->opc == INDEX_op_st_i64 && load->opc == INDEX_op_ld_vec && TCGOP_VECL(load) == 0) {
        opc = INDEX_op_movi2v_vec;
        type = 0;
        vece = MO_64;
    } else {
        return false;
    }

    mov = tcg_op_insert_before(tcg_ctx, load, opc);
    mov->args[0] = load->args[0];
    mov->args[1] = store->args[0];
    TCGOP_VECL(mov) = type;
    TCGOP_VECE(mov) = vece;
    tcg_op_remove(tcg_ctx, load);
    return true;
}

static bool brov_t0_slot(const TCGOp *op, TCGArg env, TCGArg first, TCGArg end)
{
    return op->args[1] == env && op->args[2] >= first && op->args[2] < end;
}

static bool brov_t0_read_after(TCGContext *tcg_ctx, TCGOp *store, TCGArg env, TCGArg first, TCGArg end)
{
    TCGOp *op;

    for (op = QTAILQ_NEXT(store, link); op != NULL; op = QTAILQ_NEXT(op, link)) {
        const TCGOpDef *def = &tcg_ctx->tcg_op_defs[op->opc];

        if (op->opc == INDEX_op_call) {
            return true;
        }
        if (def->nb_oargs == 1 && def->nb_iargs == 1 && def->nb_cargs >= 1 && brov_t0_slot(op, env, first, end)) {
            return true;
        }
    }
    return false;
}

/* gen_sse loads a memory operand into xmm_t0 before any path claims the instruction, and a claimed path reads it back
 * from there. The read takes the stored value instead, and the store goes when nothing else reads the slot. */
static void brov_xmm_forward_t0(TCGContext *tcg_ctx, TCGOp *before)
{
    const TCGArg env = tcgv_ptr_arg(tcg_ctx, tcg_ctx->cpu_env);
    const TCGArg first = offsetof(CPUX86State, xmm_t0);
    const TCGArg end = first + sizeof(ZMMReg);
    TCGOp *store = NULL, *forwarded = NULL, *op, *next;
    const TCGOpDef *def;

    for (op = QTAILQ_NEXT(before, link); op != NULL; op = next) {
        next = QTAILQ_NEXT(op, link);
        switch (op->opc) {
        case INDEX_op_st_vec:
        case INDEX_op_st_i64:
        case INDEX_op_st32_i64:
            if (brov_t0_slot(op, env, first, end)) {
                store = op->args[2] == first ? op : NULL;
                forwarded = NULL;
                continue;
            }
            break;
        case INDEX_op_ld_vec:
        case INDEX_op_ld32_vec:
            if (store != NULL && op->args[1] == env && op->args[2] == first &&
                brov_t0_forward(tcg_ctx, store, op)) {
                forwarded = store;
                continue;
            }
            break;
        default:
            break;
        }
        if (store == NULL) {
            continue;
        }
        def = &tcg_ctx->tcg_op_defs[op->opc];
        /* A plain temp does not live across a label or a branch, and a call or another store may write the slot. */
        if (op->opc == INDEX_op_set_label || op->opc == INDEX_op_call || (def->flags & TCG_OPF_BB_END) ||
            (def->nb_oargs == 0 && def->nb_iargs == 2 && def->nb_cargs >= 1 && brov_t0_slot(op, env, first, end)) ||
            brov_op_writes(tcg_ctx, op, store->args[0])) {
            store = NULL;
        }
    }
    if (forwarded != NULL && !brov_t0_read_after(tcg_ctx, forwarded, env, first, end)) {
        tcg_op_remove(tcg_ctx, forwarded);
    }
}

static void brov_gen_sse(CPUX86State *env, DisasContext *s, int b,
                         target_ulong pc_start, int rex_r)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGOp *before = tcg_last_op(tcg_ctx);

    s->brov_xmm_claimed = false;
    gen_sse(env, s, b, pc_start, rex_r);
    if (tcg_ctx->brov_xmm_count == 0) {
        return;
    }
    if (s->brov_xmm_claimed) {
        brov_xmm_check_claim(tcg_ctx, before);
        brov_xmm_forward_t0(tcg_ctx, before);
    } else {
        tcg_op_insert_after(tcg_ctx, before, INDEX_op_sync_xmm);
        tcg_emit_op(tcg_ctx, INDEX_op_sync_xmm_end);
    }
}

/* slot is -1 when vec is the global of an XMM register, else the env offset vec came from. */
typedef struct BrovXmmOperand {
    TCGv_vec vec;
    int slot;
} BrovXmmOperand;

static bool brov_xmm_global(TCGContext *tcg_ctx, int offset, TCGv_vec *global)
{
    const int first = offsetof(CPUX86State, xmm_regs[0]);
    const int size = sizeof(ZMMReg);

    if (offset < first || (offset - first) % size != 0 ||
        (offset - first) / size >= tcg_ctx->brov_xmm_count) {
        return false;
    }
    *global = tcg_ctx->brov_xmm[(offset - first) / size];
    return true;
}

/* bytes is how much the instruction reads, or 0 for a destination it writes whole.
 * A slot is loaded at that width only, because a narrower store does not forward to a wider load. */
static BrovXmmOperand brov_xmm_open(DisasContext *s, int offset, int bytes)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    BrovXmmOperand op;

    if (s->brov_xmm_claimed && brov_xmm_global(tcg_ctx, offset, &op.vec)) {
        op.slot = -1;
        return op;
    }

    op.slot = offset;
    if (bytes == 4) {
        op.vec = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V64);
        vec_gen_3(tcg_ctx, INDEX_op_ld32_vec, TCG_TYPE_V64, MO_32, tcgv_vec_arg(tcg_ctx, op.vec),
                  tcgv_ptr_arg(tcg_ctx, tcg_ctx->cpu_env), offset);
    } else if (bytes == 8) {
        op.vec = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V64);
        tcg_gen_ld_vec(tcg_ctx, op.vec, tcg_ctx->cpu_env, offset);
    } else {
        op.vec = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);
        if (bytes != 0) {
            tcg_gen_ld_vec(tcg_ctx, op.vec, tcg_ctx->cpu_env, offset);
        }
    }
    return op;
}

/* bytes is how much the instruction wrote, or 0 for an operand it only read. */
static void brov_xmm_close(DisasContext *s, const BrovXmmOperand *op, int bytes)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    if (op->slot < 0) {
        return;
    }
    if (bytes == 4) {
        TCGv_i64 lane = tcg_temp_new_i64(tcg_ctx);

        vec_gen_2(tcg_ctx, INDEX_op_movv2i_vec, TCG_TYPE_V64, MO_32, tcgv_i64_arg(tcg_ctx, lane),
                  tcgv_vec_arg(tcg_ctx, op->vec));
        tcg_gen_st32_i64(tcg_ctx, lane, tcg_ctx->cpu_env, op->slot);
        tcg_temp_free_i64(tcg_ctx, lane);
    } else if (bytes != 0) {
        tcg_gen_st_vec(tcg_ctx, op->vec, tcg_ctx->cpu_env, op->slot);
    }
    tcg_temp_free_vec(tcg_ctx, op->vec);
}

/* The flags go to CC_SRC, and the caller sets CC_OP_EFLAGS. */
static bool brov_gen_sse_comis(DisasContext *s, int b1, int op1_offset, int op2_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vece = b1 ? MO_64 : MO_32;
    int lane = b1 ? 8 : 4;
    BrovXmmOperand a, t;

    if (b1 > 1 ||
        tcg_can_emit_vec_op(tcg_ctx, INDEX_op_fcomi_vec, TCG_TYPE_V64, vece) <= 0) {
        return false;
    }

    brov_xmm_claim(s);
    a = brov_xmm_open(s, op1_offset, lane);
    t = brov_xmm_open(s, op2_offset, lane);
    vec_gen_3(tcg_ctx, INDEX_op_fcomi_vec, TCG_TYPE_V64, vece,
              tcgv_i64_arg(tcg_ctx, tcg_ctx->cpu_cc_src),
              tcgv_vec_arg(tcg_ctx, a.vec), tcgv_vec_arg(tcg_ctx, t.vec));
    brov_xmm_close(s, &t, 0);
    brov_xmm_close(s, &a, 0);
    return true;
}

/* A scalar operand of 4 bytes is read from its slot with ld32_vec. */
static bool brov_fp_can_emit(TCGContext *tcg_ctx, TCGOpcode opc, TCGType type, unsigned vece)
{
    return tcg_can_emit_vec_op(tcg_ctx, opc, type, vece) > 0 &&
           tcg_can_emit_vec_op(tcg_ctx, INDEX_op_ld32_vec, TCG_TYPE_V64, MO_32) > 0;
}

static bool brov_fp_cvt_ok(DisasContext *s, TCGOpcode opc, unsigned vece)
{
    return (s->flags & HF_BROV_FPN_MASK) && !brov_fp_vec_off() &&
           brov_fp_can_emit(s->uc->tcg_ctx, opc, TCG_TYPE_V64, vece);
}

/* The source is in T0. */
static bool brov_gen_cvti2f(DisasContext *s, int b, int op1_offset, bool wide)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vece = ((b >> 8) & 1) ? MO_64 : MO_32;
    int lane = vece == MO_64 ? 8 : 4;
    BrovXmmOperand d;

    if (!brov_fp_cvt_ok(s, INDEX_op_cvti2f_vec, vece)) {
        return false;
    }

    brov_xmm_claim(s);
    d = brov_xmm_open(s, op1_offset, lane);
    vec_gen_4(tcg_ctx, INDEX_op_cvti2f_vec, TCG_TYPE_V64, vece, tcgv_vec_arg(tcg_ctx, d.vec),
              tcgv_vec_arg(tcg_ctx, d.vec), tcgv_i64_arg(tcg_ctx, s->T0), wide);
    brov_xmm_close(s, &d, lane);
    return true;
}

/* Bit 0 of the opcode is set for the rounding forms and clear for the truncating ones. */
static bool brov_gen_cvtf2i(DisasContext *s, int b, int op2_offset, TCGArg out, bool wide)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vece = ((b >> 8) & 1) ? MO_64 : MO_32;
    BrovXmmOperand t;

    if (!brov_fp_cvt_ok(s, INDEX_op_cvtf2i_vec, vece)) {
        return false;
    }

    brov_xmm_claim(s);
    t = brov_xmm_open(s, op2_offset, vece == MO_64 ? 8 : 4);
    vec_gen_3(tcg_ctx, INDEX_op_cvtf2i_vec, TCG_TYPE_V64, vece, out,
              tcgv_vec_arg(tcg_ctx, t.vec), (wide ? 1 : 0) | ((b & 1) ? 0 : 2));
    brov_xmm_close(s, &t, 0);
    return true;
}

/* vece is the size of a source lane. */
static bool brov_gen_sse_fcvt(DisasContext *s, TCGOpcode opc, unsigned vece, int op1_offset, int op2_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    BrovXmmOperand d, t;

    if (opc == INDEX_op_fcvts_vec) {
        int from = vece == MO_64 ? 8 : 4;
        int to = vece == MO_64 ? 4 : 8;

        if (!brov_fp_can_emit(tcg_ctx, opc, TCG_TYPE_V64, vece)) {
            return false;
        }
        brov_xmm_claim(s);
        d = brov_xmm_open(s, op1_offset, to);
        t = brov_xmm_open(s, op2_offset, from);
        vec_gen_3(tcg_ctx, opc, TCG_TYPE_V64, vece, tcgv_vec_arg(tcg_ctx, d.vec),
                  tcgv_vec_arg(tcg_ctx, d.vec), tcgv_vec_arg(tcg_ctx, t.vec));
        brov_xmm_close(s, &t, 0);
        brov_xmm_close(s, &d, to);
        return true;
    }

    if (tcg_can_emit_vec_op(tcg_ctx, opc, TCG_TYPE_V128, vece) <= 0) {
        return false;
    }
    brov_xmm_claim(s);
    t = brov_xmm_open(s, op2_offset, 16);
    d = brov_xmm_open(s, op1_offset, 0);
    vec_gen_2(tcg_ctx, opc, TCG_TYPE_V128, vece, tcgv_vec_arg(tcg_ctx, d.vec),
              tcgv_vec_arg(tcg_ctx, t.vec));
    brov_xmm_close(s, &t, 0);
    brov_xmm_close(s, &d, 16);
    return true;
}

static bool brov_gen_sse_fp(DisasContext *s, int b, int b1,
                            int op1_offset, int op2_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    bool scalar = b1 >= 2;
    unsigned vece = (b1 & 1) ? MO_64 : MO_32;
    TCGType type = scalar ? TCG_TYPE_V64 : TCG_TYPE_V128;
    int lane = !scalar ? 16 : vece == MO_64 ? 8 : 4;
    BrovXmmOperand d, t;
    TCGOpcode opc;

    if (!(s->flags & HF_BROV_FPN_MASK) || brov_fp_vec_off()) {
        return false;
    }
    if (b == 0x2e || b == 0x2f) {
        return brov_gen_sse_comis(s, b1, op1_offset, op2_offset);
    }

    switch (b) {
    case 0x5a: /* cvtps2pd, cvtpd2ps, cvtss2sd and cvtsd2ss */
        return brov_gen_sse_fcvt(s, scalar ? INDEX_op_fcvts_vec : INDEX_op_fcvt_vec, vece, op1_offset, op2_offset);
    case 0x5b: /* cvtdq2ps */
        return b1 == 0 && brov_gen_sse_fcvt(s, INDEX_op_fcvti_vec, MO_32, op1_offset, op2_offset);
    case 0xe6: /* cvtdq2pd */
        return b1 == 2 && brov_gen_sse_fcvt(s, INDEX_op_fcvti_vec, MO_64, op1_offset, op2_offset);
    case 0x51: opc = scalar ? INDEX_op_fsqrts_vec : INDEX_op_fsqrt_vec; break;
    case 0x58: opc = INDEX_op_fadd_vec; break;
    case 0x59: opc = INDEX_op_fmul_vec; break;
    case 0x5c: opc = INDEX_op_fsub_vec; break;
    case 0x5d: opc = INDEX_op_fmin_vec; break;
    case 0x5e: opc = INDEX_op_fdiv_vec; break;
    case 0x5f: opc = INDEX_op_fmax_vec; break;
    default: return false;
    }

    if (!brov_fp_can_emit(tcg_ctx, opc, type, vece)) {
        return false;
    }

    brov_xmm_claim(s);
    if (opc == INDEX_op_fsqrt_vec) {
        t = brov_xmm_open(s, op2_offset, 16);
        d = brov_xmm_open(s, op1_offset, 0);
        vec_gen_2(tcg_ctx, opc, type, vece, tcgv_vec_arg(tcg_ctx, d.vec),
                  tcgv_vec_arg(tcg_ctx, t.vec));
    } else {
        d = brov_xmm_open(s, op1_offset, lane);
        t = brov_xmm_open(s, op2_offset, lane);
        vec_gen_3(tcg_ctx, opc, type, vece, tcgv_vec_arg(tcg_ctx, d.vec),
                  tcgv_vec_arg(tcg_ctx, d.vec), tcgv_vec_arg(tcg_ctx, t.vec));
    }
    brov_xmm_close(s, &t, 0);
    brov_xmm_close(s, &d, lane);
    return true;
}

/* Integer SSE operations that have one host vector instruction with the same
 * semantics. Bit exact, so no MXCSR condition and no NaN question.
 *
 * Claimed by helper pointer and not by opcode byte, because the generic call
 * site in gen_sse is reached from two tables: 0xdb and 0xdf are pand and pandn
 * in sse_op_table1 and AESIMC and AESDECLAST in sse_op_table6.
 *
 * op1_offset is the destination at every call site that reaches a claimed
 * helper.
 *
 * BROVAN_NO_SSEVEC=1 is the kill switch. */
enum {
    BROV_VEC_NONE = 0,
    BROV_VEC_AND,
    BROV_VEC_ANDC,
    BROV_VEC_OR,
    BROV_VEC_XOR,
    BROV_VEC_ADD,
    BROV_VEC_SUB,
    BROV_VEC_MUL,
    BROV_VEC_SSADD,
    BROV_VEC_USADD,
    BROV_VEC_SSSUB,
    BROV_VEC_USSUB,
    BROV_VEC_SMIN,
    BROV_VEC_SMAX,
    BROV_VEC_UMIN,
    BROV_VEC_UMAX,
    BROV_VEC_CMPEQ,
    BROV_VEC_CMPGT,
    BROV_VEC_ZIPL,
    BROV_VEC_ZIPH,
    BROV_VEC_PACKSS,
    BROV_VEC_PACKUS,
};

static bool brov_sse_vec_off(void)
{
    return brov_switch_set(BROV_SWITCH_NO_SSEVEC);
}

static int brov_sse_vec_kind(SSEFunc_0_epp fn, unsigned *vece)
{
#define BROV_VEC_CLAIM(helper, kind, e)                                 \
    if (fn == (SSEFunc_0_epp)gen_helper_##helper##_xmm) {               \
        *vece = (e);                                                    \
        return (kind);                                                  \
    }
    BROV_VEC_CLAIM(pand,    BROV_VEC_AND,   MO_64)
    BROV_VEC_CLAIM(pandn,   BROV_VEC_ANDC,  MO_64)
    BROV_VEC_CLAIM(por,     BROV_VEC_OR,    MO_64)
    BROV_VEC_CLAIM(pxor,    BROV_VEC_XOR,   MO_64)
    BROV_VEC_CLAIM(paddq,   BROV_VEC_ADD,   MO_64)
    BROV_VEC_CLAIM(psubq,   BROV_VEC_SUB,   MO_64)
    BROV_VEC_CLAIM(paddb,   BROV_VEC_ADD,   MO_8)
    BROV_VEC_CLAIM(paddw,   BROV_VEC_ADD,   MO_16)
    BROV_VEC_CLAIM(paddl,   BROV_VEC_ADD,   MO_32)
    BROV_VEC_CLAIM(psubb,   BROV_VEC_SUB,   MO_8)
    BROV_VEC_CLAIM(psubw,   BROV_VEC_SUB,   MO_16)
    BROV_VEC_CLAIM(psubl,   BROV_VEC_SUB,   MO_32)
    BROV_VEC_CLAIM(pmullw,  BROV_VEC_MUL,   MO_16)

    BROV_VEC_CLAIM(paddsb,  BROV_VEC_SSADD, MO_8)
    BROV_VEC_CLAIM(paddsw,  BROV_VEC_SSADD, MO_16)
    BROV_VEC_CLAIM(paddusb, BROV_VEC_USADD, MO_8)
    BROV_VEC_CLAIM(paddusw, BROV_VEC_USADD, MO_16)
    BROV_VEC_CLAIM(psubsb,  BROV_VEC_SSSUB, MO_8)
    BROV_VEC_CLAIM(psubsw,  BROV_VEC_SSSUB, MO_16)
    BROV_VEC_CLAIM(psubusb, BROV_VEC_USSUB, MO_8)
    BROV_VEC_CLAIM(psubusw, BROV_VEC_USSUB, MO_16)

    BROV_VEC_CLAIM(pminub,  BROV_VEC_UMIN,  MO_8)
    BROV_VEC_CLAIM(pmaxub,  BROV_VEC_UMAX,  MO_8)
    BROV_VEC_CLAIM(pminsw,  BROV_VEC_SMIN,  MO_16)
    BROV_VEC_CLAIM(pmaxsw,  BROV_VEC_SMAX,  MO_16)

    BROV_VEC_CLAIM(pcmpeqb, BROV_VEC_CMPEQ, MO_8)
    BROV_VEC_CLAIM(pcmpeqw, BROV_VEC_CMPEQ, MO_16)
    BROV_VEC_CLAIM(pcmpeql, BROV_VEC_CMPEQ, MO_32)
    BROV_VEC_CLAIM(pcmpgtb, BROV_VEC_CMPGT, MO_8)
    BROV_VEC_CLAIM(pcmpgtw, BROV_VEC_CMPGT, MO_16)
    BROV_VEC_CLAIM(pcmpgtl, BROV_VEC_CMPGT, MO_32)

    /* unpcklps, unpckhps, unpcklpd and unpckhpd share the last four helpers. */
    BROV_VEC_CLAIM(punpcklbw,  BROV_VEC_ZIPL, MO_8)
    BROV_VEC_CLAIM(punpcklwd,  BROV_VEC_ZIPL, MO_16)
    BROV_VEC_CLAIM(punpckhbw,  BROV_VEC_ZIPH, MO_8)
    BROV_VEC_CLAIM(punpckhwd,  BROV_VEC_ZIPH, MO_16)
    BROV_VEC_CLAIM(punpckldq,  BROV_VEC_ZIPL, MO_32)
    BROV_VEC_CLAIM(punpcklqdq, BROV_VEC_ZIPL, MO_64)
    BROV_VEC_CLAIM(punpckhdq,  BROV_VEC_ZIPH, MO_32)
    BROV_VEC_CLAIM(punpckhqdq, BROV_VEC_ZIPH, MO_64)

    BROV_VEC_CLAIM(packsswb,   BROV_VEC_PACKSS, MO_8)
    BROV_VEC_CLAIM(packssdw,   BROV_VEC_PACKSS, MO_16)
    BROV_VEC_CLAIM(packuswb,   BROV_VEC_PACKUS, MO_8)
#undef BROV_VEC_CLAIM
    return BROV_VEC_NONE;
}

static TCGOpcode brov_sse_vec_opc(int kind)
{
    switch (kind) {
    case BROV_VEC_AND:   return INDEX_op_and_vec;
    case BROV_VEC_ANDC:  return INDEX_op_andc_vec;
    case BROV_VEC_OR:    return INDEX_op_or_vec;
    case BROV_VEC_XOR:   return INDEX_op_xor_vec;
    case BROV_VEC_ADD:   return INDEX_op_add_vec;
    case BROV_VEC_SUB:   return INDEX_op_sub_vec;
    case BROV_VEC_MUL:   return INDEX_op_mul_vec;
    case BROV_VEC_SSADD: return INDEX_op_ssadd_vec;
    case BROV_VEC_USADD: return INDEX_op_usadd_vec;
    case BROV_VEC_SSSUB: return INDEX_op_sssub_vec;
    case BROV_VEC_USSUB: return INDEX_op_ussub_vec;
    case BROV_VEC_SMIN:  return INDEX_op_smin_vec;
    case BROV_VEC_SMAX:  return INDEX_op_smax_vec;
    case BROV_VEC_UMIN:  return INDEX_op_umin_vec;
    case BROV_VEC_UMAX:  return INDEX_op_umax_vec;
    case BROV_VEC_ZIPL:  return INDEX_op_zipl_vec;
    case BROV_VEC_ZIPH:  return INDEX_op_ziph_vec;
    case BROV_VEC_PACKSS: return INDEX_op_packss_vec;
    case BROV_VEC_PACKUS: return INDEX_op_packus_vec;
    default:             return INDEX_op_cmp_vec;
    }
}

/* Packed shift by immediate. x86 gives zero for a count at or above the
 * element width, or all sign bits for an arithmetic shift. */
static bool brov_gen_sse_shifti(DisasContext *s, int b, int b1, int is_xmm,
                                int val, int modrm)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    int group = ((b - 1) & 3);
    int op = (modrm >> 3) & 7;
    unsigned vece = MO_16 + group;
    int bits = 8 << vece;
    TCGOpcode opc;
    BrovXmmOperand d;
    int dst;

    if (!is_xmm || !TCG_TARGET_HAS_v128 || brov_sse_vec_off()) {
        return false;
    }
    if (!sse_op_table2[group * 8 + op][b1]) {
        return false;
    }

    switch (op) {
    case 2: opc = INDEX_op_shri_vec; break;
    case 4: opc = INDEX_op_sari_vec; break;
    case 6: opc = INDEX_op_shli_vec; break;
    default: return false;
    }
    if (tcg_can_emit_vec_op(tcg_ctx, opc, TCG_TYPE_V128, vece) == 0) {
        return false;
    }

    brov_xmm_claim(s);
    if (val == 0) {
        return true;
    }

    dst = offsetof(CPUX86State, xmm_regs[0]) +
          ((modrm & 7) | REX_B(s)) * (int)sizeof(ZMMReg);

    if (val >= bits && opc != INDEX_op_sari_vec) {
        d = brov_xmm_open(s, dst, 0);
        tcg_gen_dupi_vec(tcg_ctx, MO_64, d.vec, 0);
    } else {
        int amount = val >= bits ? bits - 1 : val;

        d = brov_xmm_open(s, dst, 16);
        if (opc == INDEX_op_shri_vec) {
            tcg_gen_shri_vec(tcg_ctx, vece, d.vec, d.vec, amount);
        } else if (opc == INDEX_op_sari_vec) {
            tcg_gen_sari_vec(tcg_ctx, vece, d.vec, d.vec, amount);
        } else {
            tcg_gen_shli_vec(tcg_ctx, vece, d.vec, d.vec, amount);
        }
    }

    brov_xmm_close(s, &d, 16);
    return true;
}

static bool brov_gen_sse_vec(DisasContext *s, SSEFunc_0_epp fn,
                             int op1_offset, int op2_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    unsigned vece = MO_64;
    BrovXmmOperand d, t;
    int kind;

    if (!TCG_TARGET_HAS_v128 || brov_sse_vec_off()) {
        return false;
    }

    kind = brov_sse_vec_kind(fn, &vece);
    if (kind == BROV_VEC_NONE) {
        return false;
    }
    if (tcg_can_emit_vec_op(tcg_ctx, brov_sse_vec_opc(kind),
                            TCG_TYPE_V128, vece) == 0) {
        return false;
    }

    brov_xmm_claim(s);
    if (op1_offset == op2_offset &&
        (kind == BROV_VEC_SUB || kind == BROV_VEC_CMPGT ||
         kind == BROV_VEC_XOR || kind == BROV_VEC_ANDC)) {
        d = brov_xmm_open(s, op1_offset, 0);
        tcg_gen_dupi_vec(tcg_ctx, MO_64, d.vec, 0);
        brov_xmm_close(s, &d, 16);
        return true;
    }

    d = brov_xmm_open(s, op1_offset, 16);
    t = brov_xmm_open(s, op2_offset, 16);

    switch (kind) {
    case BROV_VEC_AND:   tcg_gen_and_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    /* x86 inverts the destination, the opposite of the TCG operand order */
    case BROV_VEC_ANDC:  tcg_gen_andc_vec(tcg_ctx, vece, d.vec, t.vec, d.vec); break;
    case BROV_VEC_OR:    tcg_gen_or_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_XOR:   tcg_gen_xor_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_ADD:   tcg_gen_add_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_SUB:   tcg_gen_sub_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_MUL:   tcg_gen_mul_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_SSADD: tcg_gen_ssadd_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_USADD: tcg_gen_usadd_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_SSSUB: tcg_gen_sssub_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_USSUB: tcg_gen_ussub_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_SMIN:  tcg_gen_smin_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_SMAX:  tcg_gen_smax_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_UMIN:  tcg_gen_umin_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_UMAX:  tcg_gen_umax_vec(tcg_ctx, vece, d.vec, d.vec, t.vec); break;
    case BROV_VEC_ZIPL:
    case BROV_VEC_ZIPH:
    case BROV_VEC_PACKSS:
    case BROV_VEC_PACKUS:
        vec_gen_3(tcg_ctx, brov_sse_vec_opc(kind), TCG_TYPE_V128, vece, tcgv_vec_arg(tcg_ctx, d.vec),
                  tcgv_vec_arg(tcg_ctx, d.vec), tcgv_vec_arg(tcg_ctx, t.vec));
        break;
    case BROV_VEC_CMPEQ:
        tcg_gen_cmp_vec(tcg_ctx, TCG_COND_EQ, vece, d.vec, d.vec, t.vec);
        break;
    default:
        tcg_gen_cmp_vec(tcg_ctx, TCG_COND_GT, vece, d.vec, d.vec, t.vec);
        break;
    }

    brov_xmm_close(s, &t, 0);
    brov_xmm_close(s, &d, 16);
    return true;
}

/* shufpd selects pairs of 32 bit lanes, so it takes the same op as shufps. */
static bool brov_gen_sse_shuf(DisasContext *s, int b, int b1, int op1_offset, int op2_offset, int val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    bool one_source = b == 0x70 && b1 == 1;
    BrovXmmOperand d, t;

    if (!TCG_TARGET_HAS_v128 || brov_sse_vec_off() ||
        tcg_can_emit_vec_op(tcg_ctx, INDEX_op_shuf_vec, TCG_TYPE_V128, MO_32) <= 0) {
        return false;
    }
    if (b == 0xc6 && b1 == 1) {
        int low = (val & 1) * 2, high = ((val >> 1) & 1) * 2;

        val = low | ((low + 1) << 2) | (high << 4) | ((high + 1) << 6);
    } else if (!one_source && !(b == 0xc6 && b1 == 0)) {
        return false;
    }

    brov_xmm_claim(s);
    t = brov_xmm_open(s, op2_offset, 16);
    d = brov_xmm_open(s, op1_offset, one_source ? 0 : 16);
    vec_gen_4(tcg_ctx, INDEX_op_shuf_vec, TCG_TYPE_V128, MO_32, tcgv_vec_arg(tcg_ctx, d.vec),
              tcgv_vec_arg(tcg_ctx, one_source ? t.vec : d.vec), tcgv_vec_arg(tcg_ctx, t.vec), val & 0xff);
    brov_xmm_close(s, &t, 0);
    brov_xmm_close(s, &d, 16);
    return true;
}

/* The slow path passes the value through xmm_t0, which the instruction is done with by then. */
static bool brov_vecmem_ok(void)
{
    return TCG_TARGET_HAS_brov_vecmem && TCG_TARGET_HAS_v128 && !brov_switch_set(BROV_SWITCH_NO_VECMEM);
}

static void brov_gen_vecmem(DisasContext *s, TCGOpcode opc, TCGv_vec reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;

    tcg_gen_op4(tcg_ctx, opc, tcgv_vec_arg(tcg_ctx, reg), tcgv_i64_arg(tcg_ctx, s->A0),
                offsetof(CPUX86State, xmm_t0), s->mem_index);
    check_exit_request(tcg_ctx);
}

static bool brov_gen_ldo(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_vec t;

    if (!brov_vecmem_ok()) {
        return false;
    }

    t = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);
    brov_gen_vecmem(s, INDEX_op_qemu_ld_v128, t);
    tcg_gen_st_vec(tcg_ctx, t, tcg_ctx->cpu_env, offset);
    tcg_temp_free_vec(tcg_ctx, t);
    return true;
}

static bool brov_gen_sto(DisasContext *s, int offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_vec t;

    if (!brov_vecmem_ok()) {
        return false;
    }

    t = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);
    tcg_gen_ld_vec(tcg_ctx, t, tcg_ctx->cpu_env, offset);
    brov_gen_vecmem(s, INDEX_op_qemu_st_v128, t);
    tcg_temp_free_vec(tcg_ctx, t);
    return true;
}

static bool brov_gen_movo(DisasContext *s, int d_offset, int s_offset)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_vec t;

    if (!TCG_TARGET_HAS_v128 || brov_sse_vec_off()) {
        return false;
    }

    t = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);
    tcg_gen_ld_vec(tcg_ctx, t, tcg_ctx->cpu_env, s_offset);
    tcg_gen_st_vec(tcg_ctx, t, tcg_ctx->cpu_env, d_offset);
    tcg_temp_free_vec(tcg_ctx, t);
    return true;
}

static void brov_gen_lane0(TCGContext *tcg_ctx, unsigned vece, TCGv_vec d, TCGv_vec from)
{
    if (d != from) {
        vec_gen_3(tcg_ctx, INDEX_op_lane0_vec, TCG_TYPE_V128, vece, tcgv_vec_arg(tcg_ctx, d),
                  tcgv_vec_arg(tcg_ctx, d), tcgv_vec_arg(tcg_ctx, from));
    }
}

static void brov_gen_movi2v(TCGContext *tcg_ctx, unsigned vece, TCGv_vec d, TCGv_i64 from)
{
    vec_gen_2(tcg_ctx, INDEX_op_movi2v_vec, TCG_TYPE_V128, vece, tcgv_vec_arg(tcg_ctx, d),
              tcgv_i64_arg(tcg_ctx, from));
}

static void brov_gen_movv2i(TCGContext *tcg_ctx, unsigned vece, TCGv_i64 d, TCGv_vec from)
{
    vec_gen_2(tcg_ctx, INDEX_op_movv2i_vec, TCG_TYPE_V128, vece, tcgv_i64_arg(tcg_ctx, d),
              tcgv_vec_arg(tcg_ctx, from));
}

static void brov_gen_halves(TCGContext *tcg_ctx, bool high, TCGv_vec d, TCGv_vec a, TCGv_vec b)
{
    vec_gen_3(tcg_ctx, high ? INDEX_op_ziph_vec : INDEX_op_zipl_vec, TCG_TYPE_V128, MO_64,
              tcgv_vec_arg(tcg_ctx, d), tcgv_vec_arg(tcg_ctx, a), tcgv_vec_arg(tcg_ctx, b));
}

/* b is the opcode with the prefix index in bits 8 and 9. */
static bool brov_gen_sse_special(CPUX86State *env, DisasContext *s, int b, int modrm, int reg)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    bool memory = ((modrm >> 6) & 3) != 3;
    unsigned vece = MO_32;
    TCGv_vec r, m, t;
    bool halves;

    if (tcg_ctx->brov_xmm_count == 0 ||
        tcg_can_emit_vec_op(tcg_ctx, INDEX_op_lane0_vec, TCG_TYPE_V128, MO_32) <= 0 ||
        tcg_can_emit_vec_op(tcg_ctx, INDEX_op_movi2v_vec, TCG_TYPE_V128, MO_32) <= 0 ||
        tcg_can_emit_vec_op(tcg_ctx, INDEX_op_movv2i_vec, TCG_TYPE_V128, MO_32) <= 0) {
        return false;
    }
    r = tcg_ctx->brov_xmm[reg];
    m = tcg_ctx->brov_xmm[(modrm & 7) | REX_B(s)];
    halves = tcg_can_emit_vec_op(tcg_ctx, INDEX_op_zipl_vec, TCG_TYPE_V128, MO_64) > 0;

    switch (b) {
    case 0x3f0: /* lddqu */
        if (!memory) {
            return false;
        }
        /* fall through */
    case 0x010: /* movups */
    case 0x110: /* movupd */
    case 0x028: /* movaps */
    case 0x128: /* movapd */
    case 0x16f: /* movdqa */
    case 0x26f: /* movdqu */
        if (!memory) {
            brov_xmm_claim(s);
            tcg_gen_mov_vec(tcg_ctx, r, m);
            return true;
        }
        if (!brov_vecmem_ok()) {
            return false;
        }
        brov_xmm_claim(s);
        gen_lea_modrm(env, s, modrm);
        brov_gen_vecmem(s, INDEX_op_qemu_ld_v128, r);
        return true;

    case 0x1e7: /* movntdq */
    case 0x02b: /* movntps */
    case 0x12b: /* movntpd */
        if (!memory) {
            return false;
        }
        /* fall through */
    case 0x011: /* movups */
    case 0x111: /* movupd */
    case 0x029: /* movaps */
    case 0x129: /* movapd */
    case 0x17f: /* movdqa */
    case 0x27f: /* movdqu */
        if (!memory) {
            brov_xmm_claim(s);
            tcg_gen_mov_vec(tcg_ctx, m, r);
            return true;
        }
        if (!brov_vecmem_ok()) {
            return false;
        }
        brov_xmm_claim(s);
        gen_lea_modrm(env, s, modrm);
        brov_gen_vecmem(s, INDEX_op_qemu_st_v128, r);
        return true;

    case 0x310: /* movsd xmm, ea */
        vece = MO_64;
        /* fall through */
    case 0x210: /* movss xmm, ea */
        brov_xmm_claim(s);
        if (!memory) {
            brov_gen_lane0(tcg_ctx, vece, r, m);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, vece, s->tmp1_i64, s->A0);
            brov_gen_movi2v(tcg_ctx, vece, r, s->tmp1_i64);
        }
        return true;

    case 0x311: /* movsd ea, xmm */
        vece = MO_64;
        /* fall through */
    case 0x211: /* movss ea, xmm */
        brov_xmm_claim(s);
        if (!memory) {
            brov_gen_lane0(tcg_ctx, vece, m, r);
        } else {
            gen_lea_modrm(env, s, modrm);
            brov_gen_movv2i(tcg_ctx, vece, s->tmp1_i64, r);
            gen_op_st_v(s, vece, s->tmp1_i64, s->A0);
        }
        return true;

    case 0x16e: /* movd xmm, ea and movq xmm, ea */
        vece = s->dflag == MO_64 ? MO_64 : MO_32;
        brov_xmm_claim(s);
        gen_ldst_modrm(env, s, modrm, vece, OR_TMP0, 0);
        brov_gen_movi2v(tcg_ctx, vece, r, s->T0);
        return true;

    case 0x17e: /* movd ea, xmm and movq ea, xmm */
        vece = s->dflag == MO_64 ? MO_64 : MO_32;
        brov_xmm_claim(s);
        brov_gen_movv2i(tcg_ctx, vece, s->T0, r);
        gen_ldst_modrm(env, s, modrm, vece, OR_TMP0, 1);
        return true;

    case 0x27e: /* movq xmm, ea */
        brov_xmm_claim(s);
        if (!memory) {
            brov_gen_movv2i(tcg_ctx, MO_64, s->tmp1_i64, m);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_64, s->tmp1_i64, s->A0);
        }
        brov_gen_movi2v(tcg_ctx, MO_64, r, s->tmp1_i64);
        return true;

    case 0x1d6: /* movq ea, xmm */
        brov_xmm_claim(s);
        brov_gen_movv2i(tcg_ctx, MO_64, s->tmp1_i64, r);
        if (!memory) {
            brov_gen_movi2v(tcg_ctx, MO_64, m, s->tmp1_i64);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_st_v(s, MO_64, s->tmp1_i64, s->A0);
        }
        return true;

    case 0x012: /* movlps xmm, ea and movhlps */
    case 0x112: /* movlpd xmm, ea */
        if (!halves) {
            return false;
        }
        brov_xmm_claim(s);
        if (!memory) {
            brov_gen_halves(tcg_ctx, true, r, m, r);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_64, s->tmp1_i64, s->A0);
            t = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);
            brov_gen_movi2v(tcg_ctx, MO_64, t, s->tmp1_i64);
            brov_gen_lane0(tcg_ctx, MO_64, r, t);
            tcg_temp_free_vec(tcg_ctx, t);
        }
        return true;

    case 0x016: /* movhps xmm, ea and movlhps */
    case 0x116: /* movhpd xmm, ea */
        if (!halves) {
            return false;
        }
        brov_xmm_claim(s);
        if (!memory) {
            brov_gen_halves(tcg_ctx, false, r, r, m);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_64, s->tmp1_i64, s->A0);
            t = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);
            brov_gen_movi2v(tcg_ctx, MO_64, t, s->tmp1_i64);
            brov_gen_halves(tcg_ctx, false, r, r, t);
            tcg_temp_free_vec(tcg_ctx, t);
        }
        return true;

    case 0x013: /* movlps ea, xmm */
    case 0x113: /* movlpd ea, xmm */
        if (!memory) {
            return false;
        }
        brov_xmm_claim(s);
        gen_lea_modrm(env, s, modrm);
        brov_gen_movv2i(tcg_ctx, MO_64, s->tmp1_i64, r);
        gen_op_st_v(s, MO_64, s->tmp1_i64, s->A0);
        return true;

    case 0x017: /* movhps ea, xmm */
    case 0x117: /* movhpd ea, xmm */
        if (!memory || !halves) {
            return false;
        }
        brov_xmm_claim(s);
        gen_lea_modrm(env, s, modrm);
        t = tcg_temp_new_vec(tcg_ctx, TCG_TYPE_V128);
        brov_gen_halves(tcg_ctx, true, t, r, r);
        brov_gen_movv2i(tcg_ctx, MO_64, s->tmp1_i64, t);
        tcg_temp_free_vec(tcg_ctx, t);
        gen_op_st_v(s, MO_64, s->tmp1_i64, s->A0);
        return true;

    case 0x312: /* movddup */
        if (!halves) {
            return false;
        }
        brov_xmm_claim(s);
        if (!memory) {
            brov_gen_halves(tcg_ctx, false, r, m, m);
        } else {
            gen_lea_modrm(env, s, modrm);
            gen_op_ld_v(s, MO_64, s->tmp1_i64, s->A0);
            brov_gen_movi2v(tcg_ctx, MO_64, r, s->tmp1_i64);
            brov_gen_halves(tcg_ctx, false, r, r, r);
        }
        return true;

    case 0x050: /* movmskps */
    case 0x150: /* movmskpd */
    case 0x1d7: /* pmovmskb */
        vece = b == 0x050 ? MO_32 : b == 0x150 ? MO_64 : MO_8;
        if ((b == 0x1d7 && memory) ||
            tcg_can_emit_vec_op(tcg_ctx, INDEX_op_movmsk_vec, TCG_TYPE_V128, vece) <= 0) {
            return false;
        }
        brov_xmm_claim(s);
        vec_gen_2(tcg_ctx, INDEX_op_movmsk_vec, TCG_TYPE_V128, vece,
                  tcgv_i64_arg(tcg_ctx, tcg_ctx->cpu_regs[reg]), tcgv_vec_arg(tcg_ctx, m));
        return true;

    case 0x212: /* movsldup */
    case 0x216: /* movshdup */
        if (tcg_can_emit_vec_op(tcg_ctx, INDEX_op_shuf_vec, TCG_TYPE_V128, MO_32) <= 0 ||
            (memory && !brov_vecmem_ok())) {
            return false;
        }
        brov_xmm_claim(s);
        if (memory) {
            gen_lea_modrm(env, s, modrm);
            brov_gen_vecmem(s, INDEX_op_qemu_ld_v128, r);
            m = r;
        }
        vec_gen_4(tcg_ctx, INDEX_op_shuf_vec, TCG_TYPE_V128, MO_32, tcgv_vec_arg(tcg_ctx, r),
                  tcgv_vec_arg(tcg_ctx, m), tcgv_vec_arg(tcg_ctx, m), b == 0x212 ? 0xa0 : 0xf5);
        return true;

    default:
        return false;
    }
}

#endif
