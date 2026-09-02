/* Brovan extensions to Unicorn. Applied to the upstream tree at build time by
 * Brovan.Unicorn.targets; see patches.manifest for the anchor list.
 *
 * This header is pulled into uc_priv.h and tcg.h, so it must not depend on any
 * Unicorn or QEMU type.
 */
#ifndef BROVAN_UC_H
#define BROVAN_UC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define BROV_ABI_VERSION 3u
#define BROV_BLOB_MAGIC 0x4356524Bu /* "KRVC" */

/* Blocks translated in budget mode carry a decrement the others do not, so a
 * blob is only interchangeable with a run in the same mode. */
#define BROV_BLOB_FLAG_BUDGET 0x1u

/* The reservation is laid out [slot table][arena][code gen buffer]. Replaying a
 * single base address therefore pins every object whose address gets baked into
 * generated code. */
#define BROV_SLOT_AREA_SIZE (64u * 1024u)
#define BROV_ARENA_SIZE (64u * 1024u)
#define BROV_RESERVE_HEADER_SIZE (BROV_SLOT_AREA_SIZE + BROV_ARENA_SIZE)
#define BROV_MAX_SLOTS (BROV_SLOT_AREA_SIZE / sizeof(void *))
#define BROV_DEFAULT_SLOTS 4096u

/* Fraction of restored blocks that may fail guest-source verification before the
 * whole blob is discarded: a mostly-invalidated cache is slower than none. */
#define BROV_MAX_STALE_PERCENT 25u

typedef enum brov_reason {
    BROV_OK = 0,
    BROV_REASON_NO_RESERVATION,
    BROV_REASON_UNSUPPORTED_TARGET,
    BROV_REASON_TRUNCATED,
    BROV_REASON_MAGIC,
    BROV_REASON_ABI,
    BROV_REASON_LAYOUT,
    BROV_REASON_HOST,
    BROV_REASON_TARGET,
    BROV_REASON_BASE_MISMATCH,
    BROV_REASON_PROLOGUE,
    BROV_REASON_ARENA_MISMATCH,
    BROV_REASON_CODE_HASH,
    BROV_REASON_SLOT_OVERFLOW,
    BROV_REASON_AUDIT,
    BROV_REASON_TOO_MANY_STALE,
    BROV_REASON_EMPTY,
    BROV_REASON_BLOATED,
    BROV_REASON_SLOT_UNRESOLVED,
    BROV_REASON_BUDGET,
    BROV_REASON_MAX
} brov_reason;

/* Slot contents are not all the same kind of thing. Helpers live in unicorn's
 * image and are stored relative to it; a hook callback is a host callback the
 * embedder registered - for Brovan a .NET thunk, which lands somewhere new every
 * run - so it is stored as the identity of the hook that owns it and looked up
 * again on load. */
#define BROV_SLOT_IMAGE 0u
#define BROV_SLOT_HOOK 1u

typedef struct brov_slot_record_t {
    uint32_t kind;
    uint32_t hook_idx;  /* BROV_SLOT_HOOK: which uc->hook[] list */
    uint64_t detail;    /* BROV_SLOT_IMAGE: offset from the image anchor */
    uint64_t tag;       /* BROV_SLOT_HOOK: identity of the owning hook */
} brov_slot_record_t;

/* Restored blocks that later turn out to be unusable leave their code behind:
 * nothing can move it, because other blocks branch to it by absolute address.
 * Once the buffer is mostly dead weight the blob is dropped so the next save
 * starts compact again. */
#define BROV_MIN_LIVE_PERCENT 50u

/* brov_configure() flags. */
#define BROV_CFG_ENABLE_CACHE 0x1u
#define BROV_CFG_STRICT_AUDIT 0x2u /* also flag pointers into the interior of a tracked object */

typedef struct brov_config_t {
    uint32_t struct_size;
    uint32_t flags;
    uint64_t reserve_base; /* 0: let the OS choose and report it back */
    uint64_t reserve_size; /* 0: default */
    uint32_t slot_count;   /* 0: BROV_DEFAULT_SLOTS */
    uint32_t reserved;
} brov_config_t;

typedef struct brov_cc_info_t {
    uint32_t struct_size;
    uint32_t last_reason;

    uint64_t reservation_base;
    uint64_t reservation_size;
    uint64_t code_gen_buffer;
    uint64_t code_gen_buffer_size;
    uint64_t code_gen_used;

    uint64_t tb_count;
    uint64_t flush_count;

    uint32_t slot_count;
    uint32_t slots_used;
    uint32_t slots_overflowed;

    uint64_t load_count;
    uint64_t loaded_tbs;
    uint64_t stale_tbs;
    uint64_t save_count;
} brov_cc_info_t;

/* Populated by a failed audit so the offending site can be reported rather than
 * silently dropped. */
typedef struct brov_audit_result_t {
    uint32_t struct_size;
    uint32_t hit_count;
    uint64_t first_offset;
    uint64_t first_value;
    char first_object[32];
    uint32_t first_context_before;
    uint32_t first_context_bytes;
    uint8_t first_context[48];
} brov_audit_result_t;

typedef struct brov_blob_header_t {
    uint32_t magic;
    uint32_t abi;
    uint32_t header_bytes;
    uint32_t flags;

    uint64_t layout_fingerprint;
    uint64_t host_fingerprint;
    uint32_t target_arch;
    uint32_t target_mode;

    uint64_t reservation_base;
    uint64_t reservation_size;
    uint64_t code_gen_buffer_off;
    uint64_t code_gen_buffer_size;
    uint64_t code_gen_used;

    uint64_t prologue_hash;
    uint64_t prologue_bytes;

    uint64_t uc_off;
    uint64_t tcg_ctx_off;
    uint64_t arena_used;

    uint64_t region_current;
    uint64_t region_agg_size_full;

    uint32_t slot_count;
    uint32_t slots_used;
    uint64_t tb_count;

    uint64_t code_hash;
} brov_blob_header_t;

typedef struct brov_tb_record_t {
    uint64_t offset; /* from code_gen_buffer */
    uint64_t src_hash;
} brov_tb_record_t;

struct uc_struct;

/* rdtsc answered in helper_rdtsc from the embedder's clock, as counts since
 * host_start at qpc_freq, plus the skew, times the TSC ticks per count. */
typedef struct brov_tsc_t {
    uint32_t armed;
    uint32_t reserved;
    int64_t host_start;
    int64_t host_freq;
    int64_t qpc_freq;
    int64_t skew_counts;
    uint64_t tsc_per_qpc;
} brov_tsc_t;

/* brov_reg_ptr flags. A register is only writable through its pointer when
 * uc_reg_write() would have done nothing but store to it: the program counter is
 * excluded because writing it also raises quit_request and flushes translated
 * blocks. */
#define BROV_REG_READABLE 0x1u
#define BROV_REG_WRITABLE 0x2u

/* Installed from inside the per-target translation unit, which is the only place
 * TCGContext and TranslationBlock are complete types. Mirrors how Unicorn wires
 * up uc->tb_flush / uc->uc_gen_tb. */
struct brov_ops {
    int (*info)(struct uc_struct *uc, brov_cc_info_t *out);
    int (*audit)(struct uc_struct *uc, brov_audit_result_t *out);
    int (*save)(struct uc_struct *uc, void **blob, size_t *len);
    int (*load)(struct uc_struct *uc, const void *blob, size_t len);
    int (*resolve)(struct uc_struct *uc, uint32_t *resolved, uint32_t *remaining);
    int (*reg_ptr)(struct uc_struct *uc, int regid, void **ptr, size_t *size, uint32_t *flags);
    void (*set_budget)(struct uc_struct *uc, int32_t budget);
    int32_t *(*budget_ptr)(struct uc_struct *uc);
};

#define BROVAN_UC_FIELDS                                                       \
    uint32_t brov_last_reason;                                                 \
    uint32_t brov_budget_mode;                                                 \
    void *brov_ram_starts;                                                     \
    unsigned brov_ram_starts_cap;                                              \
    uint32_t brov_mem_hook_sig;                                                \
    brov_tsc_t brov_tsc;                                                       \
    struct brov_ops brov;

#define BROVAN_TCG_FIELDS                                                      \
    void **brov_slots;                                                         \
    uint32_t *brov_slot_map;                                                   \
    uint32_t brov_slot_count;                                                  \
    uint32_t brov_slot_map_mask;                                               \
    uint32_t brov_slots_used;                                                  \
    uint32_t brov_slots_overflowed;                                            \
    uint64_t brov_prologue_hash;                                               \
    uint64_t brov_prologue_bytes;                                              \
    uint64_t brov_load_count;                                                  \
    uint64_t brov_loaded_tbs;                                                  \
    uint64_t brov_stale_tbs;                                                   \
    uint64_t brov_save_count;                                                  \
    void *brov_pending;                                                        \
    uint64_t brov_pending_count;                                               \
    uint64_t brov_pending_flush;                                               \
    struct TCGLabel *brov_exitreq_label;                                       \
    struct TCGOp *brov_budget_insns;

/* The slot table is interned during code generation (inside the tcg.c
 * translation unit) and rebuilt after a load (inside translate-all.c). Both
 * need the identical probe sequence, so it lives here. */
static inline uint32_t brov_slot_hash(const void *fn)
{
    uint64_t v = (uint64_t)(uintptr_t)fn >> 4;
    v *= 0x9e3779b97f4a7c15ULL;
    return (uint32_t)(v >> 32);
}

/* Returns the index of an existing slot, or the map bucket to fill (via
 * *bucket) when the pointer is not interned yet. */
static inline uint32_t brov_slot_find(void *const *slots, const uint32_t *map,
                                      uint32_t mask, const void *fn,
                                      uint32_t *bucket)
{
    uint32_t i = brov_slot_hash(fn) & mask;

    for (;;) {
        uint32_t entry = map[i];
        if (entry == 0) {
            *bucket = i;
            return (uint32_t)-1;
        }
        if (slots[entry - 1] == fn) {
            return entry - 1;
        }
        i = (i + 1) & mask;
    }
}

static inline uint32_t brov_slot_intern(void **slots, uint32_t *map, uint32_t mask,
                                        uint32_t *used, uint32_t count, const void *fn)
{
    uint32_t bucket = 0;
    uint32_t idx = brov_slot_find(slots, map, mask, fn, &bucket);

    if (idx != (uint32_t)-1) {
        return idx;
    }
    if (*used >= count) {
        return (uint32_t)-1;
    }
    idx = (*used)++;
    slots[idx] = (void *)(uintptr_t)fn;
    map[bucket] = idx + 1;
    return idx;
}

/* Defined in brovan_uc_api.inc.c (appended to uc.c) and therefore global to the
 * whole library; the per-target implementations are all static. */
void *brov_alloc_uc(size_t size);
void brov_free_uc(void *p);
void *brov_alloc_arena(size_t size);
bool brov_reservation(uint64_t *base, uint64_t *size, uint32_t *slot_count);
uint64_t brov_arena_offset(const void *p);
uint64_t brov_arena_used(void);
uintptr_t brov_image_base(void);
bool brov_image_range(uint64_t *lo, uint64_t *hi);
uint64_t brov_hash_bytes(const void *data, size_t len, uint64_t seed);
bool brov_cache_requested(void);
bool brov_strict_audit(void);
bool brov_commit_rwx(void *addr, uint64_t size);
void brov_arm_budget(struct uc_struct *uc, size_t count);
uint32_t brov_budget_mode_wanted(struct uc_struct *uc);
uint32_t brov_access_exit_check_elided(struct uc_struct *uc);
uint64_t brov_tsc_now(struct uc_struct *uc);

#endif /* BROVAN_UC_H */
