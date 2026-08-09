/* Appended to qemu/accel/tcg/translate-all.c, which is compiled once per target
 * and is the only place TranslationBlock, TCGContext and this file's page-list
 * statics are all in scope. Everything here is static; uc->brov is the only way
 * in from outside. */

#if defined(TARGET_I386)
#include "unicorn/x86.h"
#define BROV_TARGET_SUPPORTED 1
#elif defined(TARGET_AARCH64)
#include "unicorn/arm64.h"
/* translate-a64.c bakes ARMCPRegInfo heap pointers into generated code, which
 * nothing here pins; the audit would reject every save anyway. */
#define BROV_TARGET_SUPPORTED 0
#else
#define BROV_TARGET_SUPPORTED 0
#endif

/* TARGET_PAGE_SIZE is a runtime value on some targets, so this cannot be sized
 * from it. A TB never covers more than one page. */
#define BROV_MAX_TB_SRC 16384

#define BROV_TB_DROPPED 0
#define BROV_TB_READY 1
#define BROV_TB_PENDING 2

static bool brov_owns_buffer;

/* Opt-in tracing of why blocks were kept, dropped or deferred. Resolved once:
 * some of the callers below are per-block. */
static bool brov_dump(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = getenv("BROVAN_JIT_AUDIT_DUMP") != NULL;
    }
    return enabled != 0;
}

static bool brov_owns_code_gen_buffer(struct uc_struct *uc)
{
    (void)uc;
    return brov_owns_buffer;
}

static bool brov_try_alloc_code_gen_buffer(struct uc_struct *uc, size_t tb_size)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    uint64_t base = 0, size = 0;
    uint32_t slots = 0, map_entries;
    uint8_t *code;
    size_t code_size, want;

    if (!brov_reservation(&base, &size, &slots)) {
        return false;
    }

    code = (uint8_t *)(uintptr_t)base + BROV_RESERVE_HEADER_SIZE;
    code_size = (size_t)(size - BROV_RESERVE_HEADER_SIZE);
    want = size_code_gen_buffer(tb_size);
    if (want < code_size) {
        code_size = want;
    }

#ifdef _WIN32
    /* alloc_code_gen_buffer() is also what installs the vectored handler that
     * commits code pages on first touch; the buffer it returns is discarded and
     * the handler then bounds-checks the initial_buffer set below. */
    {
        void *scratch;
        tcg_ctx->code_gen_buffer_size = code_size;
        scratch = alloc_code_gen_buffer(uc);
        if (!scratch) {
            return false;
        }
        VirtualFree(scratch, 0, MEM_RELEASE);
    }
#endif

    if (!brov_commit_rwx(code, code_size)) {
        return false;
    }

    map_entries = 16;
    while (map_entries < slots * 2u) {
        map_entries <<= 1;
    }

    tcg_ctx->brov_slots = (void **)(uintptr_t)base;
    tcg_ctx->brov_slot_map = g_malloc0(map_entries * sizeof(uint32_t));
    tcg_ctx->brov_slot_map_mask = map_entries - 1;
    tcg_ctx->brov_slot_count = slots;
    tcg_ctx->brov_slots_used = 0;
    tcg_ctx->brov_slots_overflowed = 0;

    tcg_ctx->code_gen_buffer_size = code_size;
    tcg_ctx->code_gen_buffer = code;
    tcg_ctx->initial_buffer = code;
    tcg_ctx->initial_buffer_size = code_size;
    uc->tcg_buffer_size = (uint32_t)code_size;
    brov_owns_buffer = true;
    return true;
}

static uint64_t brov_layout_fingerprint(void)
{
    uint64_t v[24];
    int n = 0;

    v[n++] = sizeof(TranslationBlock);
    v[n++] = offsetof(TranslationBlock, pc);
    v[n++] = offsetof(TranslationBlock, cs_base);
    v[n++] = offsetof(TranslationBlock, flags);
    v[n++] = offsetof(TranslationBlock, size);
    v[n++] = offsetof(TranslationBlock, cflags);
    v[n++] = offsetof(TranslationBlock, tc);
    v[n++] = offsetof(TranslationBlock, page_next);
    v[n++] = offsetof(TranslationBlock, page_addr);
    v[n++] = offsetof(TranslationBlock, jmp_reset_offset);
    v[n++] = offsetof(TranslationBlock, jmp_target_arg);
    v[n++] = offsetof(TranslationBlock, jmp_list_head);
    v[n++] = offsetof(TranslationBlock, jmp_dest);
    v[n++] = offsetof(TranslationBlock, hash);
    v[n++] = sizeof(TCGContext);
    v[n++] = offsetof(TCGContext, code_gen_buffer);
    v[n++] = offsetof(TCGContext, code_gen_ptr);
    v[n++] = offsetof(TCGContext, brov_slots);
    v[n++] = sizeof(struct uc_struct);
    v[n++] = offsetof(struct uc_struct, brov);
    v[n++] = sizeof(CPUArchState);
    v[n++] = TARGET_LONG_BITS;
    v[n++] = BROV_ABI_VERSION;

    return brov_hash_bytes(v, (size_t)n * sizeof(uint64_t), 0x62726f76616eULL);
}

static uint64_t brov_host_fingerprint(struct uc_struct *uc)
{
    uint64_t v[6];
    int n = 0;

    v[n++] = sizeof(void *);
    v[n++] = uc->qemu_real_host_page_size;
    v[n++] = (uint64_t)TARGET_PAGE_SIZE;
    v[n++] = (uint64_t)uc->qemu_icache_linesize;
    v[n++] = TCG_TARGET_REG_BITS;
    v[n++] = TCG_TARGET_NB_REGS;

    return brov_hash_bytes(v, (size_t)n * sizeof(uint64_t), 0x686f7374ULL);
}

static uint64_t brov_prologue_bytes(struct uc_struct *uc)
{
    TCGContext *s = uc->tcg_ctx;
    return (uint64_t)((uint8_t *)s->code_gen_buffer - (uint8_t *)s->initial_buffer);
}

/* Reads guest memory without faulting: a page the guest has since unmapped has
 * to read as a miss rather than crash the host mid-load. */
static bool brov_read_guest(struct uc_struct *uc, uint64_t addr, void *dst, size_t len)
{
    uint8_t *out = (uint8_t *)dst;

    while (len) {
        uint64_t page_end = (addr | (uint64_t)(TARGET_PAGE_SIZE - 1)) + 1;
        size_t chunk = (size_t)(page_end - addr);

        if (chunk > len) {
            chunk = len;
        }
        if (!uc->memory_mapping(uc, addr)) {
            return false;
        }
        if (!uc->read_mem(&uc->address_space_memory, addr, out, (int)chunk)) {
            return false;
        }
        addr += chunk;
        out += chunk;
        len -= chunk;
    }
    return true;
}

/* Hashes the guest instructions the block was translated from, so a reload can
 * drop blocks whose source has changed. Addressed through tb->pc rather than
 * page_addr[], which holds ram-block offsets and not guest addresses. */
static bool brov_tb_src_hash(struct uc_struct *uc, TranslationBlock *tb, uint64_t *out)
{
    uint8_t buf[BROV_MAX_TB_SRC];
    size_t total = tb->size;

    if (total == 0 || total > sizeof(buf)) {
        return false;
    }
    if (!brov_read_guest(uc, tb->pc, buf, total)) {
        return false;
    }

    *out = brov_hash_bytes(buf, total, tb->pc ^ ((uint64_t)tb->flags << 32));
    return true;
}

typedef struct {
    TranslationBlock **tbs;
    size_t count;
    size_t cap;
    bool oom;
} brov_tb_list;

static gboolean brov_collect_tb(gpointer key, gpointer value, gpointer data)
{
    brov_tb_list *list = (brov_tb_list *)data;
    TranslationBlock *tb = (TranslationBlock *)value;

    (void)key;

    if (tb_cflags(tb) & (CF_NOCACHE | CF_INVALID)) {
        return FALSE;
    }
    if (tb->page_addr[0] == (tb_page_addr_t)-1) {
        return FALSE;
    }

    if (list->count == list->cap) {
        size_t cap = list->cap ? list->cap * 2 : 1024;
        TranslationBlock **grown =
            (TranslationBlock **)realloc(list->tbs, cap * sizeof(*grown));
        if (!grown) {
            list->oom = true;
            return TRUE;
        }
        list->tbs = grown;
        list->cap = cap;
    }
    list->tbs[list->count++] = tb;
    return FALSE;
}

/* ---- relocation audit -------------------------------------------------- */

/* Any host pointer baked into generated code that is neither pinned in the
 * reservation nor routed through the slot table would point at the wrong object
 * after a reload. Rather than trust the static enumeration, a save scans the
 * emitted bytes for such values and refuses instead of writing a poisoned blob. */

typedef struct {
    uint64_t addr;
    const char *name;
} brov_tracked;

typedef struct {
    brov_tracked *items;
    size_t count;
    uint64_t lo;
    uint64_t hi;
    uint64_t image_lo;
    uint64_t image_hi;
    uint64_t env_lo;
    uint64_t env_hi;
} brov_track_set;

#define BROV_IMAGE_WINDOW (64ull * 1024ull * 1024ull)

static int brov_tracked_cmp(const void *a, const void *b)
{
    uint64_t x = ((const brov_tracked *)a)->addr;
    uint64_t y = ((const brov_tracked *)b)->addr;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static void brov_track_add(brov_track_set *set, size_t cap, const void *p, const char *name)
{
    uint64_t v = (uint64_t)(uintptr_t)p;

    if (!v || set->count >= cap) {
        return;
    }
    set->items[set->count].addr = v;
    set->items[set->count].name = name;
    set->count++;
}

static bool brov_build_track_set(struct uc_struct *uc, brov_track_set *set)
{
    uint64_t anchor = (uint64_t)brov_image_base();
    size_t cap = 64;
    int i;

    for (i = 0; i < UC_HOOK_MAX; i++) {
        struct list_item *cur;
        for (cur = uc->hook[i].head; cur; cur = cur->next) {
            cap += 3;
        }
    }

    memset(set, 0, sizeof(*set));
    set->items = (brov_tracked *)calloc(cap, sizeof(brov_tracked));
    if (!set->items) {
        return false;
    }

    brov_track_add(set, cap, uc->cpu, "CPUState");
    brov_track_add(set, cap, uc->cpu ? uc->cpu->env_ptr : NULL, "CPUArchState");
    brov_track_add(set, cap, uc->l1_map, "l1_map");
    brov_track_add(set, cap, uc->tcg_ctx->brov_slot_map, "slot_map");

    for (i = 0; i < UC_HOOK_MAX; i++) {
        struct list_item *cur;
        for (cur = uc->hook[i].head; cur; cur = cur->next) {
            struct hook *hk = (struct hook *)cur->data;
            brov_track_add(set, cap, hk, "hook");
            brov_track_add(set, cap, hk->callback, "hook.callback");
            brov_track_add(set, cap, hk->user_data, "hook.user_data");
        }
    }

    qsort(set->items, set->count, sizeof(brov_tracked), brov_tracked_cmp);

    if (!brov_image_range(&set->image_lo, &set->image_hi)) {
        set->image_lo = anchor > BROV_IMAGE_WINDOW ? anchor - BROV_IMAGE_WINDOW : 0;
        set->image_hi = anchor + BROV_IMAGE_WINDOW;
    }

    set->env_lo = 0;
    set->env_hi = 0;
    if (brov_strict_audit() && uc->cpu && uc->cpu->env_ptr) {
        set->env_lo = (uint64_t)(uintptr_t)uc->cpu->env_ptr;
        set->env_hi = set->env_lo + sizeof(CPUArchState);
    }

    set->lo = set->image_lo;
    set->hi = set->image_hi;
    if (set->count) {
        if (set->items[0].addr < set->lo) {
            set->lo = set->items[0].addr;
        }
        if (set->items[set->count - 1].addr > set->hi) {
            set->hi = set->items[set->count - 1].addr;
        }
    }
    if (set->env_hi) {
        if (set->env_lo < set->lo) {
            set->lo = set->env_lo;
        }
        if (set->env_hi > set->hi) {
            set->hi = set->env_hi;
        }
    }
    return true;
}

static uint64_t brov_hook_tag(const struct hook *hk)
{
    uint64_t v[4];

    v[0] = (uint64_t)(uint32_t)hk->type;
    v[1] = (uint64_t)(uint32_t)hk->insn;
    v[2] = hk->begin;
    v[3] = hk->end;
    return brov_hash_bytes(v, sizeof(v), 0x686f6f6bULL);
}

/* Describes a slot in terms that survive a restart. */
static bool brov_classify_slot(struct uc_struct *uc, uint64_t value, brov_slot_record_t *out)
{
    uint64_t anchor = (uint64_t)brov_image_base();
    uint64_t delta = value > anchor ? value - anchor : anchor - value;
    int i;

    memset(out, 0, sizeof(*out));

    if (delta < BROV_IMAGE_WINDOW) {
        out->kind = BROV_SLOT_IMAGE;
        out->detail = value - anchor;
        return true;
    }

    for (i = 0; i < UC_HOOK_MAX; i++) {
        struct list_item *cur;
        for (cur = uc->hook[i].head; cur; cur = cur->next) {
            struct hook *hk = (struct hook *)cur->data;
            if ((uint64_t)(uintptr_t)hk->callback == value) {
                out->kind = BROV_SLOT_HOOK;
                out->hook_idx = (uint32_t)i;
                out->tag = brov_hook_tag(hk);
                return true;
            }
        }
    }

    return false;
}

static bool brov_resolve_slot(struct uc_struct *uc, const brov_slot_record_t *rec, void **out)
{
    struct list_item *cur;
    void *found = NULL;
    unsigned matches = 0;

    if (rec->kind == BROV_SLOT_IMAGE) {
        *out = (void *)(uintptr_t)(brov_image_base() + rec->detail);
        return true;
    }
    if (rec->kind != BROV_SLOT_HOOK || rec->hook_idx >= UC_HOOK_MAX) {
        return false;
    }

    /* Matched on identity rather than position: hooks can be registered in a
     * different order, but two hooks identical in type, instruction and range
     * would be ambiguous and are refused. */
    for (cur = uc->hook[rec->hook_idx].head; cur; cur = cur->next) {
        struct hook *hk = (struct hook *)cur->data;
        if (brov_hook_tag(hk) == rec->tag) {
            found = hk->callback;
            matches++;
        }
    }

    if (matches != 1 || !found) {
        return false;
    }
    *out = found;
    return true;
}

static bool brov_is_slot_value(struct uc_struct *uc, uint64_t v)
{
    uint32_t i;
    for (i = 0; i < uc->tcg_ctx->brov_slots_used; i++) {
        if ((uint64_t)(uintptr_t)uc->tcg_ctx->brov_slots[i] == v) {
            return true;
        }
    }
    return false;
}

static int brov_audit_impl(struct uc_struct *uc, brov_audit_result_t *out)
{
    TCGContext *s = uc->tcg_ctx;
    const uint8_t *code = (const uint8_t *)s->code_gen_buffer;
    size_t used = (size_t)((uint8_t *)s->code_gen_ptr - (uint8_t *)s->code_gen_buffer);
    brov_track_set set;
    size_t i;
    bool dump = brov_dump();

    out->hit_count = 0;
    out->first_offset = 0;
    out->first_value = 0;
    memset(out->first_object, 0, sizeof(out->first_object));

    if (used < 8) {
        return UC_ERR_OK;
    }
    if (!brov_build_track_set(uc, &set)) {
        return UC_ERR_NOMEM;
    }

    for (i = 0; i + 8 <= used; i++) {
        const char *name = NULL;
        size_t lo, hi;
        uint64_t v;

        memcpy(&v, code + i, 8);
        if (v < set.lo || v > set.hi) {
            continue;
        }

        lo = 0;
        hi = set.count;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (set.items[mid].addr < v) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        if (lo < set.count && set.items[lo].addr == v) {
            name = set.items[lo].name;
        } else if (v >= set.image_lo && v <= set.image_hi && !brov_is_slot_value(uc, v)) {
            name = "unicorn image";
        } else if (set.env_hi && v > set.env_lo && v < set.env_hi) {
            name = "CPUArchState interior";
        }

        if (name) {
            if (out->hit_count == 0) {
                size_t n = strlen(name);
                if (n >= sizeof(out->first_object)) {
                    n = sizeof(out->first_object) - 1;
                }
                memcpy(out->first_object, name, n);
                out->first_offset = (uint64_t)i;
                out->first_value = v;
            }
            if (dump && out->hit_count < 32) {
                size_t ctx = i > 8 ? i - 8 : 0;
                int b;
                fprintf(stderr, "[brov-audit] +0x%08zx %016llx (%s) image%+lld ctx:",
                        i, (unsigned long long)v, name,
                        (long long)(v - (uint64_t)brov_image_base()));
                for (b = 0; b < 24 && ctx + b < used; b++) {
                    fprintf(stderr, "%s%02x", ctx + b == i ? " |" : " ", code[ctx + b]);
                }
                fprintf(stderr, "\n");
            }
            out->hit_count++;
        }
    }

    free(set.items);
    return UC_ERR_OK;
}

/* ---- save -------------------------------------------------------------- */

static int brov_save_impl(struct uc_struct *uc, void **blob_out, size_t *len_out)
{
    TCGContext *s = uc->tcg_ctx;
    brov_blob_header_t hdr;
    brov_audit_result_t audit;
    brov_tb_list list;
    brov_tb_record_t *records = NULL;
    uint64_t base = 0, size = 0;
    uint32_t slots = 0;
    size_t used, slot_bytes, tb_bytes, total, i, kept = 0;
    uint8_t *blob, *p;
    brov_slot_record_t *slot_section;
    bool dump = brov_dump();
    int err;

    *blob_out = NULL;
    *len_out = 0;

    if (!BROV_TARGET_SUPPORTED) {
        uc->brov_last_reason = BROV_REASON_UNSUPPORTED_TARGET;
        return UC_ERR_ARG;
    }
    if (!brov_reservation(&base, &size, &slots) || !brov_owns_buffer ||
        brov_arena_offset(uc) == (uint64_t)-1 || brov_arena_offset(s) == (uint64_t)-1) {
        uc->brov_last_reason = BROV_REASON_NO_RESERVATION;
        return UC_ERR_RESOURCE;
    }
    if (s->brov_slots_overflowed) {
        uc->brov_last_reason = BROV_REASON_SLOT_OVERFLOW;
        return UC_ERR_RESOURCE;
    }

    used = (size_t)((uint8_t *)s->code_gen_ptr - (uint8_t *)s->code_gen_buffer);
    if (used == 0) {
        uc->brov_last_reason = BROV_REASON_EMPTY;
        return UC_ERR_ARG;
    }

    audit.struct_size = sizeof(audit);
    err = brov_audit_impl(uc, &audit);
    if (err != UC_ERR_OK) {
        return err;
    }
    if (audit.hit_count) {
        uc->brov_last_reason = BROV_REASON_AUDIT;
        return UC_ERR_RESOURCE;
    }

    memset(&list, 0, sizeof(list));
    tcg_tb_foreach(s, brov_collect_tb, &list);
    if (list.oom) {
        free(list.tbs);
        return UC_ERR_NOMEM;
    }
    if (list.count == 0) {
        free(list.tbs);
        uc->brov_last_reason = BROV_REASON_EMPTY;
        return UC_ERR_ARG;
    }

    records = (brov_tb_record_t *)malloc(list.count * sizeof(*records));
    if (!records) {
        free(list.tbs);
        return UC_ERR_NOMEM;
    }

    for (i = 0; i < list.count; i++) {
        TranslationBlock *tb = list.tbs[i];
        uint64_t src;

        if (!brov_tb_src_hash(uc, tb, &src)) {
            if (dump && i < 8) {
                fprintf(stderr,
                        "[brov-save] unreadable tb pc=%llx page0=%llx page1=%llx size=%u mapped=%d\n",
                        (unsigned long long)tb->pc, (unsigned long long)tb->page_addr[0],
                        (unsigned long long)tb->page_addr[1], (unsigned)tb->size,
                        uc->memory_mapping(uc, tb->page_addr[0]) != NULL);
            }
            continue;
        }
        records[kept].offset = (uint64_t)((uint8_t *)tb - (uint8_t *)s->code_gen_buffer);
        records[kept].src_hash = src;
        kept++;
    }
    if (dump) {
        fprintf(stderr, "[brov-save] used=%zu tbs=%zu kept=%zu\n", used, list.count, kept);
    }
    free(list.tbs);

    if (kept == 0) {
        free(records);
        uc->brov_last_reason = BROV_REASON_EMPTY;
        return UC_ERR_ARG;
    }

    slot_bytes = (size_t)s->brov_slots_used * sizeof(brov_slot_record_t);
    tb_bytes = kept * sizeof(brov_tb_record_t);
    total = sizeof(hdr) + slot_bytes + tb_bytes + used;

    blob = (uint8_t *)malloc(total);
    if (!blob) {
        free(records);
        return UC_ERR_NOMEM;
    }

    p = blob + sizeof(hdr);
    slot_section = (brov_slot_record_t *)p;
    for (i = 0; i < s->brov_slots_used; i++) {
        if (!brov_classify_slot(uc, (uint64_t)(uintptr_t)s->brov_slots[i], &slot_section[i])) {
            free(blob);
            free(records);
            uc->brov_last_reason = BROV_REASON_SLOT_UNRESOLVED;
            return UC_ERR_RESOURCE;
        }
    }
    p += slot_bytes;
    memcpy(p, records, tb_bytes);
    p += tb_bytes;
    memcpy(p, s->code_gen_buffer, used);
    free(records);

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = BROV_BLOB_MAGIC;
    hdr.abi = BROV_ABI_VERSION;
    hdr.header_bytes = (uint32_t)sizeof(hdr);
    hdr.flags = uc->brov_budget_mode ? BROV_BLOB_FLAG_BUDGET : 0u;
    hdr.layout_fingerprint = brov_layout_fingerprint();
    hdr.host_fingerprint = brov_host_fingerprint(uc);
    hdr.target_arch = (uint32_t)uc->arch;
    hdr.target_mode = (uint32_t)uc->mode;
    hdr.reservation_base = base;
    hdr.reservation_size = size;
    hdr.code_gen_buffer_off =
        (uint64_t)((uint8_t *)s->code_gen_buffer - (uint8_t *)(uintptr_t)base);
    hdr.code_gen_buffer_size = s->code_gen_buffer_size;
    hdr.code_gen_used = used;
    hdr.prologue_bytes = brov_prologue_bytes(uc);
    hdr.prologue_hash = brov_hash_bytes(s->initial_buffer, (size_t)hdr.prologue_bytes, 0);
    hdr.uc_off = brov_arena_offset(uc);
    hdr.tcg_ctx_off = brov_arena_offset(s);
    hdr.arena_used = brov_arena_used();
    hdr.region_current = s->region.current;
    hdr.region_agg_size_full = s->region.agg_size_full;
    hdr.slot_count = s->brov_slot_count;
    hdr.slots_used = s->brov_slots_used;
    hdr.tb_count = kept;
    hdr.code_hash = brov_hash_bytes(s->code_gen_buffer, used, 0);
    memcpy(blob, &hdr, sizeof(hdr));

    s->brov_save_count++;
    uc->brov_last_reason = BROV_OK;
    *blob_out = blob;
    *len_out = total;
    return UC_ERR_OK;
}

/* ---- load -------------------------------------------------------------- */

/* page_addr[] and hash hold ram-block offsets from the run that generated the
 * block. Nothing guarantees the guest lands in the same ram offsets this time,
 * and a block filed under a stale page would be missed by the invalidation that
 * self-modifying code relies on, so both are recomputed from the live mapping. */
static bool brov_retarget_tb(struct uc_struct *uc, TranslationBlock *tb)
{
    CPUArchState *env = (CPUArchState *)uc->cpu->env_ptr;
    tb_page_addr_t phys_pc, phys_page2 = -1;
    target_ulong virt_page2;
    bool ok = false;

    uc->nested_level++;
    if (sigsetjmp(uc->jmp_bufs[uc->nested_level - 1], 0) != 0) {
        uc->nested_level--;
        return false;
    }

    phys_pc = get_page_addr_code(env, tb->pc);
    if (phys_pc != (tb_page_addr_t)-1) {
        virt_page2 = (tb->pc + tb->size - 1) & TARGET_PAGE_MASK;
        if ((tb->pc & TARGET_PAGE_MASK) != virt_page2) {
            phys_page2 = get_page_addr_code(env, virt_page2);
        }
        ok = phys_page2 != (tb_page_addr_t)-1 || (tb->pc & TARGET_PAGE_MASK) == virt_page2;
    }
    uc->nested_level--;

    if (!ok) {
        return false;
    }

    tb->page_addr[0] = phys_pc & TARGET_PAGE_MASK;
    tb->page_addr[1] = phys_page2;
    tb->hash = tb_hash_func(phys_pc, tb->pc, tb->flags, tb->cflags & CF_HASH_MASK,
                            tb->trace_vcpu_dstate);
    return true;
}

static bool brov_relink_tb(struct uc_struct *uc, TranslationBlock *tb)
{
    PageDesc *p = NULL, *p2 = NULL;
    void *existing = NULL;
    tb_page_addr_t phys1, phys2;

    if (!brov_retarget_tb(uc, tb)) {
        return false;
    }

    phys1 = tb->page_addr[0];
    phys2 = tb->page_addr[1];

    tb->jmp_list_head = (uintptr_t)NULL;
    tb->jmp_list_next[0] = (uintptr_t)NULL;
    tb->jmp_list_next[1] = (uintptr_t)NULL;
    tb->jmp_dest[0] = (uintptr_t)NULL;
    tb->jmp_dest[1] = (uintptr_t)NULL;
    tb->orig_tb = NULL;
    tb->cflags &= ~CF_INVALID;

    page_lock_pair(uc, &p, phys1, &p2, phys2, 1);
    if (!p) {
        return false;
    }
    tb_page_add(uc, p, tb, 0, phys1);
    if (p2) {
        tb_page_add(uc, p2, tb, 1, phys2);
    } else {
        tb->page_addr[1] = -1;
    }

    qht_insert(uc, &uc->tcg_ctx->tb_ctx.htable, tb, tb->hash, &existing);
    if (existing) {
        tb_page_remove(p, tb);
        invalidate_page_bitmap(p);
        if (p2) {
            tb_page_remove(p2, tb);
            invalidate_page_bitmap(p2);
        }
        if (p2 && p2 != p) {
            page_unlock(p2);
        }
        page_unlock(p);
        return false;
    }

    if (p2 && p2 != p) {
        page_unlock(p2);
    }
    page_unlock(p);

    tcg_tb_insert(uc->tcg_ctx, tb);

    /* Restored blocks start unchained. Anything still sitting in the buffer that
     * did not get registered - a block that failed verification, or one the save
     * skipped - must not be reachable through a stale direct jump. */
    if (tb->jmp_reset_offset[0] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 0);
    }
    if (tb->jmp_reset_offset[1] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 1);
    }
    return true;
}

static int brov_load_impl(struct uc_struct *uc, const void *blob, size_t len)
{
    TCGContext *s = uc->tcg_ctx;
    const brov_blob_header_t *hdr = (const brov_blob_header_t *)blob;
    const brov_slot_record_t *slot_section;
    const brov_tb_record_t *tb_section;
    const uint8_t *code_section;
    uint64_t base = 0, size = 0;
    uint32_t slots = 0, reason = BROV_REASON_MAGIC;
    uint8_t *usable = NULL;
    size_t expect, i, stale = 0, live = 0, unreadable = 0, changed = 0, live_bytes = 0;

    if (!BROV_TARGET_SUPPORTED) {
        uc->brov_last_reason = BROV_REASON_UNSUPPORTED_TARGET;
        return UC_ERR_ARG;
    }
    if (len < sizeof(*hdr)) {
        uc->brov_last_reason = BROV_REASON_TRUNCATED;
        return UC_ERR_ARG;
    }
    if (hdr->magic != BROV_BLOB_MAGIC) {
        uc->brov_last_reason = BROV_REASON_MAGIC;
        return UC_ERR_ARG;
    }
    if (hdr->abi != BROV_ABI_VERSION || hdr->header_bytes != sizeof(*hdr)) {
        uc->brov_last_reason = BROV_REASON_ABI;
        return UC_ERR_ARG;
    }

    expect = sizeof(*hdr) + (size_t)hdr->slots_used * sizeof(brov_slot_record_t) +
             (size_t)hdr->tb_count * sizeof(brov_tb_record_t) + (size_t)hdr->code_gen_used;
    if (len < expect || hdr->tb_count == 0) {
        uc->brov_last_reason = hdr->tb_count ? BROV_REASON_TRUNCATED : BROV_REASON_EMPTY;
        return UC_ERR_ARG;
    }

    if (!brov_reservation(&base, &size, &slots) || !brov_owns_buffer ||
        brov_arena_offset(uc) == (uint64_t)-1) {
        reason = BROV_REASON_NO_RESERVATION;
        goto reject;
    }
    if (hdr->layout_fingerprint != brov_layout_fingerprint()) {
        reason = BROV_REASON_LAYOUT;
        goto reject;
    }
    if (hdr->host_fingerprint != brov_host_fingerprint(uc)) {
        reason = BROV_REASON_HOST;
        goto reject;
    }
    if (hdr->target_arch != (uint32_t)uc->arch || hdr->target_mode != (uint32_t)uc->mode) {
        reason = BROV_REASON_TARGET;
        goto reject;
    }
    if (((hdr->flags & BROV_BLOB_FLAG_BUDGET) != 0) != (uc->brov_budget_mode != 0)) {
        reason = BROV_REASON_TARGET;
        goto reject;
    }
    if (hdr->reservation_base != base || hdr->reservation_size != size ||
        hdr->slot_count != s->brov_slot_count || hdr->slots_used > s->brov_slot_count) {
        reason = BROV_REASON_BASE_MISMATCH;
        goto reject;
    }
    if (hdr->code_gen_buffer_off !=
            (uint64_t)((uint8_t *)s->code_gen_buffer - (uint8_t *)(uintptr_t)base) ||
        hdr->code_gen_buffer_size != s->code_gen_buffer_size ||
        hdr->code_gen_used > s->code_gen_buffer_size) {
        reason = BROV_REASON_BASE_MISMATCH;
        goto reject;
    }
    if (hdr->prologue_bytes != brov_prologue_bytes(uc) ||
        hdr->prologue_hash !=
            brov_hash_bytes(s->initial_buffer, (size_t)hdr->prologue_bytes, 0)) {
        /* A different host CPU generates a different prologue, which shifts every
         * block address in the buffer. */
        reason = BROV_REASON_PROLOGUE;
        goto reject;
    }
    if (hdr->uc_off != brov_arena_offset(uc) || hdr->tcg_ctx_off != brov_arena_offset(s)) {
        reason = BROV_REASON_ARENA_MISMATCH;
        goto reject;
    }

    slot_section = (const brov_slot_record_t *)((const uint8_t *)blob + sizeof(*hdr));
    tb_section = (const brov_tb_record_t *)(slot_section + hdr->slots_used);
    code_section = (const uint8_t *)(tb_section + hdr->tb_count);

    if (hdr->code_hash != brov_hash_bytes(code_section, (size_t)hdr->code_gen_used, 0)) {
        reason = BROV_REASON_CODE_HASH;
        goto reject;
    }

    usable = (uint8_t *)calloc((size_t)hdr->tb_count, 1);
    if (!usable) {
        return UC_ERR_NOMEM;
    }

    uc_tb_flush(uc);

    memcpy(s->code_gen_buffer, code_section, (size_t)hdr->code_gen_used);
    s->code_gen_ptr = (uint8_t *)s->code_gen_buffer + hdr->code_gen_used;

    memset(s->brov_slot_map, 0, ((size_t)s->brov_slot_map_mask + 1) * sizeof(uint32_t));
    s->brov_slots_used = 0;
    s->brov_slots_overflowed = 0;
    for (i = 0; i < hdr->slots_used; i++) {
        void *fn = NULL;

        if (!brov_resolve_slot(uc, &slot_section[i], &fn)) {
            reason = BROV_REASON_SLOT_UNRESOLVED;
            goto reject_flush;
        }
        if (brov_slot_intern(s->brov_slots, s->brov_slot_map, s->brov_slot_map_mask,
                             &s->brov_slots_used, s->brov_slot_count, fn) != (uint32_t)i) {
            reason = BROV_REASON_SLOT_OVERFLOW;
            goto reject_flush;
        }
    }

    {
        bool dump = brov_dump();

        for (i = 0; i < hdr->tb_count; i++) {
            TranslationBlock *tb;
            uint64_t src;

            if (tb_section[i].offset + sizeof(TranslationBlock) > hdr->code_gen_used) {
                stale++;
                continue;
            }
            tb = (TranslationBlock *)((uint8_t *)s->code_gen_buffer + tb_section[i].offset);
            if (!brov_tb_src_hash(uc, tb, &src)) {
                if (dump && unreadable < 4) {
                    fprintf(stderr, "[brov-load] unreadable pc=%llx size=%u\n",
                            (unsigned long long)tb->pc, (unsigned)tb->size);
                }
                unreadable++;
                stale++;
                usable[i] = BROV_TB_PENDING;
                continue;
            }
            if (src != tb_section[i].src_hash) {
                if (dump && changed < 4) {
                    fprintf(stderr, "[brov-load] changed pc=%llx size=%u\n",
                            (unsigned long long)tb->pc, (unsigned)tb->size);
                }
                changed++;
                stale++;
                continue;
            }
            usable[i] = BROV_TB_READY;
        }

        for (i = 0; i < hdr->tb_count; i++) {
            if (usable[i] != BROV_TB_DROPPED &&
                tb_section[i].offset + sizeof(TranslationBlock) <= hdr->code_gen_used) {
                TranslationBlock *tb =
                    (TranslationBlock *)((uint8_t *)s->code_gen_buffer + tb_section[i].offset);
                live_bytes += sizeof(TranslationBlock) + tb->tc.size;
            }
        }

        if (dump) {
            fprintf(stderr,
                    "[brov-load] tbs=%llu stale=%zu unreadable=%zu changed=%zu live=%zu/%llu\n",
                    (unsigned long long)hdr->tb_count, stale, unreadable, changed, live_bytes,
                    (unsigned long long)hdr->code_gen_used);
        }
    }

    if (live_bytes * 100u < (size_t)hdr->code_gen_used * BROV_MIN_LIVE_PERCENT) {
        reason = BROV_REASON_BLOATED;
        goto reject_flush;
    }

    /* Only blocks whose guest bytes actually differ say the blob is wrong. A page
     * the loader has not mapped yet is expected: much of the program is still
     * being brought in when execution starts. Those blocks are dropped either
     * way, they just do not count as evidence against the whole cache. */
    if (changed * 100u > (uint64_t)hdr->tb_count * BROV_MAX_STALE_PERCENT) {
        s->brov_stale_tbs = stale;
        s->brov_loaded_tbs = 0;
        reason = BROV_REASON_TOO_MANY_STALE;
        goto reject_flush;
    }

    for (i = 0; i < hdr->tb_count; i++) {
        TranslationBlock *tb;

        if (usable[i] != BROV_TB_READY) {
            continue;
        }
        tb = (TranslationBlock *)((uint8_t *)s->code_gen_buffer + tb_section[i].offset);
        if (brov_relink_tb(uc, tb)) {
            live++;
        }
    }

    /* Blocks in pages the loader has not reached yet keep their code in the
     * buffer; registering them later is what stops the next save from carrying
     * both the restored copy and a freshly translated duplicate. */
    free(s->brov_pending);
    s->brov_pending = NULL;
    s->brov_pending_count = 0;
    if (unreadable) {
        brov_tb_record_t *pend = (brov_tb_record_t *)malloc(unreadable * sizeof(*pend));
        if (pend) {
            size_t n = 0;
            for (i = 0; i < hdr->tb_count && n < unreadable; i++) {
                if (usable[i] == BROV_TB_PENDING) {
                    pend[n++] = tb_section[i];
                }
            }
            s->brov_pending = pend;
            s->brov_pending_count = n;
            s->brov_pending_flush = s->tb_ctx.tb_flush_count;
        }
    }

    cpu_tb_jmp_cache_clear(uc->cpu);
    free(usable);

    s->brov_load_count++;
    s->brov_loaded_tbs = live;
    s->brov_stale_tbs = stale;
    uc->brov_last_reason = BROV_OK;
    return UC_ERR_OK;

reject_flush:
    uc_tb_flush(uc);
reject:
    free(usable);
    uc->brov_last_reason = reason;
    return UC_ERR_ARG;
}

/* Retries the blocks whose pages were not mapped when the blob was loaded. Their
 * code is already sitting in the buffer, so this only has to verify and file
 * them; nothing is translated and nothing grows. */
static int brov_resolve_impl(struct uc_struct *uc, uint32_t *resolved, uint32_t *remaining)
{
    TCGContext *s = uc->tcg_ctx;
    brov_tb_record_t *pend = (brov_tb_record_t *)s->brov_pending;
    size_t kept = 0, done = 0, i;
    bool dump = brov_dump();

    if (resolved) {
        *resolved = 0;
    }
    if (remaining) {
        *remaining = 0;
    }
    if (!pend || !s->brov_pending_count) {
        return UC_ERR_OK;
    }

    /* A flush reuses the buffer, so the pending offsets no longer name the
     * blocks they were recorded for. */
    if (s->tb_ctx.tb_flush_count != s->brov_pending_flush) {
        free(pend);
        s->brov_pending = NULL;
        s->brov_pending_count = 0;
        return UC_ERR_OK;
    }

    for (i = 0; i < s->brov_pending_count; i++) {
        TranslationBlock *tb =
            (TranslationBlock *)((uint8_t *)s->code_gen_buffer + pend[i].offset);
        uint64_t src;

        if (!brov_tb_src_hash(uc, tb, &src)) {
            pend[kept++] = pend[i];
            continue;
        }
        if (src != pend[i].src_hash) {
            continue;
        }
        if (brov_relink_tb(uc, tb)) {
            done++;
        }
    }

    if (dump && done) {
        fprintf(stderr, "[brov-resolve] resolved=%zu still-pending=%zu\n", done, kept);
    }

    s->brov_pending_count = kept;
    s->brov_loaded_tbs += done;
    if (!kept) {
        free(pend);
        s->brov_pending = NULL;
    }

    if (done) {
        cpu_tb_jmp_cache_clear(uc->cpu);
    }
    if (resolved) {
        *resolved = (uint32_t)done;
    }
    if (remaining) {
        *remaining = (uint32_t)kept;
    }
    return UC_ERR_OK;
}

/* ---- info / flush / registers ------------------------------------------ */

static int brov_info_impl(struct uc_struct *uc, brov_cc_info_t *out)
{
    TCGContext *s = uc->tcg_ctx;
    uint64_t base = 0, size = 0;
    uint32_t slots = 0;

    brov_reservation(&base, &size, &slots);

    out->last_reason = uc->brov_last_reason;
    out->reservation_base = base;
    out->reservation_size = size;
    out->code_gen_buffer = (uint64_t)(uintptr_t)s->code_gen_buffer;
    out->code_gen_buffer_size = s->code_gen_buffer_size;
    out->code_gen_used =
        (uint64_t)((uint8_t *)s->code_gen_ptr - (uint8_t *)s->code_gen_buffer);
    out->tb_count = tcg_nb_tbs(s);
    out->flush_count = s->tb_ctx.tb_flush_count;
    out->slot_count = s->brov_slot_count;
    out->slots_used = s->brov_slots_used;
    out->slots_overflowed = s->brov_slots_overflowed;
    out->load_count = s->brov_load_count;
    out->loaded_tbs = s->brov_loaded_tbs;
    out->stale_tbs = s->brov_stale_tbs;
    out->save_count = s->brov_save_count;
    return UC_ERR_OK;
}

/* The pointers below stay valid for the lifetime of uc: Unicorn allocates
 * CPUState once and never moves it. */
#if defined(TARGET_I386)
static int brov_reg_ptr_impl(struct uc_struct *uc, int regid, void **ptr, size_t *size,
                             uint32_t *flags)
{
    CPUX86State *env;

    if (!uc->cpu || !uc->cpu->env_ptr) {
        return UC_ERR_HANDLE;
    }
    /* 16- and 32-bit modes reach the same storage through different rules -
     * reg_write() zero-extends EAX there but preserves the upper half in 64-bit
     * mode - so only the unambiguous 64-bit ids are handed out. */
    if (!(uc->mode & UC_MODE_64)) {
        return UC_ERR_ARG;
    }
    env = (CPUX86State *)uc->cpu->env_ptr;
    *flags = BROV_REG_READABLE | BROV_REG_WRITABLE;

    if (regid >= UC_X86_REG_XMM0 && regid <= UC_X86_REG_XMM31) {
        int n = regid - UC_X86_REG_XMM0;
        if (n >= (int)ARRAY_SIZE(env->xmm_regs)) {
            return UC_ERR_ARG;
        }
        *ptr = &env->xmm_regs[n];
        if (size) {
            *size = 16;
        }
        return UC_ERR_OK;
    }

    switch (regid) {
    case UC_X86_REG_RAX: *ptr = &env->regs[R_EAX]; break;
    case UC_X86_REG_RCX: *ptr = &env->regs[R_ECX]; break;
    case UC_X86_REG_RDX: *ptr = &env->regs[R_EDX]; break;
    case UC_X86_REG_RBX: *ptr = &env->regs[R_EBX]; break;
    case UC_X86_REG_RSP: *ptr = &env->regs[R_ESP]; break;
    case UC_X86_REG_RBP: *ptr = &env->regs[R_EBP]; break;
    case UC_X86_REG_RSI: *ptr = &env->regs[R_ESI]; break;
    case UC_X86_REG_RDI: *ptr = &env->regs[R_EDI]; break;
#ifdef TARGET_X86_64
    case UC_X86_REG_R8: *ptr = &env->regs[8]; break;
    case UC_X86_REG_R9: *ptr = &env->regs[9]; break;
    case UC_X86_REG_R10: *ptr = &env->regs[10]; break;
    case UC_X86_REG_R11: *ptr = &env->regs[11]; break;
    case UC_X86_REG_R12: *ptr = &env->regs[12]; break;
    case UC_X86_REG_R13: *ptr = &env->regs[13]; break;
    case UC_X86_REG_R14: *ptr = &env->regs[14]; break;
    case UC_X86_REG_R15: *ptr = &env->regs[15]; break;
#endif
    case UC_X86_REG_RIP:
        /* Readable only: uc_reg_write() also sets quit_request and flushes the
         * translated blocks, which a bare store would skip. */
        *ptr = &env->eip;
        *flags = BROV_REG_READABLE;
        break;
    case UC_X86_REG_FS_BASE: *ptr = &env->segs[R_FS].base; break;
    case UC_X86_REG_GS_BASE: *ptr = &env->segs[R_GS].base; break;
    default:
        /* EFLAGS is deliberately absent: env->eflags omits the lazily evaluated
         * condition codes, so a raw pointer would not hold the architectural
         * value that uc_reg_read() computes. */
        return UC_ERR_ARG;
    }

    if (size) {
        *size = sizeof(target_ulong);
    }
    return UC_ERR_OK;
}
#elif defined(TARGET_AARCH64)
static int brov_reg_ptr_impl(struct uc_struct *uc, int regid, void **ptr, size_t *size,
                             uint32_t *flags)
{
    CPUARMState *env;

    if (!uc->cpu || !uc->cpu->env_ptr) {
        return UC_ERR_HANDLE;
    }
    env = (CPUARMState *)uc->cpu->env_ptr;
    *flags = BROV_REG_READABLE | BROV_REG_WRITABLE;

    if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
        *ptr = &env->xregs[regid - UC_ARM64_REG_X0];
    } else if (regid == UC_ARM64_REG_X29) {
        *ptr = &env->xregs[29];
    } else if (regid == UC_ARM64_REG_X30) {
        *ptr = &env->xregs[30];
    } else if (regid == UC_ARM64_REG_SP) {
        *ptr = &env->xregs[31];
    } else if (regid == UC_ARM64_REG_PC) {
        *ptr = &env->pc;
        *flags = BROV_REG_READABLE;
    } else {
        return UC_ERR_ARG;
    }

    if (size) {
        *size = sizeof(uint64_t);
    }
    return UC_ERR_OK;
}
#else
static int brov_reg_ptr_impl(struct uc_struct *uc, int regid, void **ptr, size_t *size,
                             uint32_t *flags)
{
    (void)uc;
    (void)regid;
    (void)ptr;
    (void)size;
    (void)flags;
    return UC_ERR_ARG;
}
#endif

static void brov_set_budget_impl(struct uc_struct *uc, int32_t budget)
{
    cpu_neg(uc->cpu)->brov_insn_budget = budget;
}

static void brov_install(struct uc_struct *uc)
{
    uc->brov.info = brov_info_impl;
    uc->brov.audit = brov_audit_impl;
    uc->brov.save = brov_save_impl;
    uc->brov.load = brov_load_impl;
    uc->brov.resolve = brov_resolve_impl;
    uc->brov.reg_ptr = brov_reg_ptr_impl;
    uc->brov.set_budget = brov_set_budget_impl;

    /* Starts on so that the first uc_emu_start() does not have to flush the
     * blocks a restored cache just installed. */
    uc->brov_budget_mode = 1;
}
