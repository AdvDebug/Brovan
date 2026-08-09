/* Appended to uc.c. Arch-neutral half of the Brovan extensions: the address
 * reservation, the arena that pins uc/tcg_ctx, and the exported entry points.
 * Everything that needs TCGContext or TranslationBlock lives in
 * brovan_uc_tcg.inc.c and is reached through uc->brov. */

#ifndef _WIN32
#include <sys/mman.h>
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#endif

/* Address of an object in our own image. Slot contents are stored relative to
 * this rather than to the module base, so no OS module-lookup is needed and the
 * delta stays constant however the loader places the library. */
static const char brov_image_anchor_obj = 0;

static struct {
    uint8_t *base;
    uint64_t size;
    uint32_t slot_count;
    uint8_t *arena;
    size_t arena_used;
    bool active;
    bool cache_requested;
    bool strict_audit;
} g_brov;

static bool brov_os_reserve(void *want, uint64_t size, void **got)
{
#ifdef _WIN32
    void *p = VirtualAlloc(want, (SIZE_T)size, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p || (want && p != want)) {
        if (p) {
            VirtualFree(p, 0, MEM_RELEASE);
        }
        return false;
    }
    *got = p;
    return true;
#else
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *p;

    /* MAP_FIXED would silently unmap whatever is already there, and
     * MAP_FIXED_NOREPLACE needs Linux 4.17 which Android kernels predate, so
     * fall back to a hint and check what we actually got. */
    if (want) {
        p = mmap(want, (size_t)size, PROT_NONE, flags | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED) {
            p = mmap(want, (size_t)size, PROT_NONE, flags, -1, 0);
        }
    } else {
        p = mmap(NULL, (size_t)size, PROT_NONE, flags, -1, 0);
    }

    if (p == MAP_FAILED) {
        return false;
    }
    if (want && p != want) {
        munmap(p, (size_t)size);
        return false;
    }
    *got = p;
    return true;
#endif
}

static void brov_os_release(void *base, uint64_t size)
{
#ifdef _WIN32
    (void)size;
    VirtualFree(base, 0, MEM_RELEASE);
#else
    munmap(base, (size_t)size);
#endif
}

static bool brov_os_commit_rw(void *addr, uint64_t size)
{
#ifdef _WIN32
    return VirtualAlloc(addr, (SIZE_T)size, MEM_COMMIT, PAGE_READWRITE) != NULL;
#else
    return mprotect(addr, (size_t)size, PROT_READ | PROT_WRITE) == 0;
#endif
}

bool brov_commit_rwx(void *addr, uint64_t size)
{
#ifdef _WIN32
    /* Left reserved on Windows: the vectored handler installed by
     * alloc_code_gen_buffer() commits code pages on first touch. */
    (void)addr;
    (void)size;
    return true;
#else
    return mprotect(addr, (size_t)size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
#endif
}

/* A saved cache can only be reloaded at the address it was generated for, so the
 * base has to be reproducible across runs. Letting the OS pick is not: the CLR
 * has usually taken part of that range by the next launch. These are tried in
 * order and each is verified, never assumed - the last entry is small enough to
 * sit under a 39-bit user VA, which older Android kernels still use. */
static const uint64_t brov_preferred_bases[] = {
    0x0000100000000000ull,
    0x0000004000000000ull,
    0x0000000200000000ull,
};

static bool brov_reserve_somewhere(uint64_t wanted, uint64_t size, void **got)
{
    size_t i;

    if (wanted && brov_os_reserve((void *)(uintptr_t)wanted, size, got)) {
        return true;
    }

    for (i = 0; i < sizeof(brov_preferred_bases) / sizeof(brov_preferred_bases[0]); i++) {
        if (brov_preferred_bases[i] == wanted) {
            continue;
        }
        if (brov_os_reserve((void *)(uintptr_t)brov_preferred_bases[i], size, got)) {
            return true;
        }
    }

    return brov_os_reserve(NULL, size, got);
}

uintptr_t brov_image_base(void)
{
    return (uintptr_t)&brov_image_anchor_obj;
}

/* Where this library is actually mapped. The audit needs real bounds: guessing a
 * window around the anchor flags ordinary constants as image pointers whenever the
 * code buffer happens to land near the library, which is the common case on
 * Android. */
bool brov_image_range(uint64_t *lo, uint64_t *hi)
{
    uintptr_t anchor = (uintptr_t)&brov_image_anchor_obj;

#ifdef _WIN32
    MEMORY_BASIC_INFORMATION info;

    if (VirtualQuery((LPCVOID)anchor, &info, sizeof(info)) == sizeof(info) && info.AllocationBase) {
        const uint8_t *base = (const uint8_t *)info.AllocationBase;
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;

        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.SizeOfImage) {
                *lo = (uint64_t)(uintptr_t)base;
                *hi = *lo + nt->OptionalHeader.SizeOfImage;
                return true;
            }
        }
    }
    return false;
#else
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[512];
    char owner[256];
    bool found = false;

    if (!maps) {
        return false;
    }

    owner[0] = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start, end;
        char path[256];
        int fields;

        path[0] = 0;
        fields = sscanf(line, "%llx-%llx %*s %*s %*s %*s %255s", &start, &end, path);
        if (fields < 2) {
            continue;
        }

        if (!found) {
            if (anchor < start || anchor >= end) {
                continue;
            }
            /* Anonymous mapping: nothing to extend over, take this range alone. */
            if (!path[0]) {
                *lo = start;
                *hi = end;
                fclose(maps);
                return true;
            }
            snprintf(owner, sizeof(owner), "%s", path);
            *lo = start;
            *hi = end;
            found = true;
            continue;
        }

        /* The library spans several segments; keep extending while they belong to it. */
        if (path[0] && strcmp(path, owner) == 0 && start <= *hi) {
            *hi = end;
        } else if (start > *hi) {
            break;
        }
    }

    fclose(maps);

    if (found) {
        /* The first segment may not be the lowest one, so sweep again for the start. */
        maps = fopen("/proc/self/maps", "r");
        if (maps) {
            while (fgets(line, sizeof(line), maps)) {
                unsigned long long start, end;
                char path[256];

                path[0] = 0;
                if (sscanf(line, "%llx-%llx %*s %*s %*s %*s %255s", &start, &end, path) >= 3 &&
                    strcmp(path, owner) == 0 && start < *lo) {
                    *lo = start;
                }
            }
            fclose(maps);
        }
    }

    return found;
#endif
}

uint64_t brov_hash_bytes(const void *data, size_t len, uint64_t seed)
{
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = seed ^ ((uint64_t)len * 0x9e3779b97f4a7c15ULL);
    uint64_t k;

    while (len >= 8) {
        memcpy(&k, p, 8);
        k *= 0xff51afd7ed558ccdULL;
        k ^= k >> 33;
        h ^= k;
        h *= 0xc4ceb9fe1a85ec53ULL;
        h = (h << 31) | (h >> 33);
        p += 8;
        len -= 8;
    }
    if (len) {
        k = 0;
        memcpy(&k, p, len);
        k *= 0xff51afd7ed558ccdULL;
        h ^= k;
        h *= 0xc4ceb9fe1a85ec53ULL;
    }

    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

bool brov_reservation(uint64_t *base, uint64_t *size, uint32_t *slot_count)
{
    if (!g_brov.active) {
        return false;
    }
    if (base) {
        *base = (uint64_t)(uintptr_t)g_brov.base;
    }
    if (size) {
        *size = g_brov.size;
    }
    if (slot_count) {
        *slot_count = g_brov.slot_count;
    }
    return true;
}

bool brov_cache_requested(void)
{
    return g_brov.active && g_brov.cache_requested;
}

bool brov_strict_audit(void)
{
    return g_brov.strict_audit;
}

uint64_t brov_arena_offset(const void *p)
{
    if (!g_brov.active || (const uint8_t *)p < g_brov.arena ||
        (const uint8_t *)p >= g_brov.arena + BROV_ARENA_SIZE) {
        return (uint64_t)-1;
    }
    return (uint64_t)((const uint8_t *)p - g_brov.base);
}

uint64_t brov_arena_used(void)
{
    return (uint64_t)g_brov.arena_used;
}

static void *brov_arena_alloc(size_t size)
{
    size_t aligned = (size + 63u) & ~(size_t)63u;
    void *p;

    if (!g_brov.active || g_brov.arena_used + aligned > BROV_ARENA_SIZE) {
        return NULL;
    }
    p = g_brov.arena + g_brov.arena_used;
    g_brov.arena_used += aligned;
    memset(p, 0, size);
    return p;
}

/* The uc struct is baked into generated code by tcg_const_ptr(uc), so it has to
 * land at the same address on every run for a restored cache to be valid. */
void *brov_alloc_uc(size_t size)
{
    void *p = brov_arena_alloc(size);
    return p ? p : calloc(1, size);
}

void brov_free_uc(void *p)
{
    if (g_brov.active && (uint8_t *)p >= g_brov.arena &&
        (uint8_t *)p < g_brov.arena + BROV_ARENA_SIZE) {
        return;
    }
    free(p);
}

void *brov_alloc_arena(size_t size)
{
    void *p = brov_arena_alloc(size);
    return p ? p : g_malloc0(size);
}

/* Picks between Unicorn's per-instruction count hook and the per-block budget,
 * and programs the counter for this uc_emu_start(). Exactness is only
 * observable through an embedder code hook, and that path already pays the
 * per-instruction preamble the budget exists to avoid, so it keeps the hook. */
void brov_arm_budget(struct uc_struct *uc, size_t count)
{
    int foreign_code_hooks;
    uint32_t want;
    static int disabled = -1;

    if (disabled < 0) {
        /* Kill switch: the budget changes when a slice ends and how the guest
         * PC is recovered, so keep a way to fall back to Unicorn's own counting
         * without a rebuild. */
        disabled = getenv("BROVAN_NO_BUDGET") != NULL;
    }

    if (disabled || !uc->brov.set_budget) {
        if (uc->brov_budget_mode) {
            uc->brov_budget_mode = 0;
            uc->tb_flush(uc);
        }
        return;
    }

    foreign_code_hooks = uc->hooks_count[UC_HOOK_CODE_IDX] - (uc->count_hook ? 1 : 0);
    want = foreign_code_hooks > 0 ? 0u : 1u;

    if (want != uc->brov_budget_mode) {
        uc->brov_budget_mode = want;
        uc->tb_flush(uc);
    }

    if (!want) {
        return;
    }

    if (uc->count_hook) {
        uc_hook_del(uc, uc->count_hook);
        uc->count_hook = 0;
        uc->tb_flush(uc);
    }

    uc->brov.set_budget(uc, count > 0 && count < (size_t)INT32_MAX ? (int32_t)count
                                                                  : INT32_MAX);
}

UNICORN_EXPORT
uc_err brov_abi_version(uint32_t *abi)
{
    if (!abi) {
        return UC_ERR_ARG;
    }
    *abi = BROV_ABI_VERSION;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err brov_configure(const brov_config_t *cfg)
{
    uint64_t size;
    uint32_t slots;
    void *got = NULL;

    if (!cfg || cfg->struct_size != sizeof(brov_config_t)) {
        return UC_ERR_ARG;
    }
    if (g_brov.active) {
        return UC_ERR_OK;
    }

    slots = cfg->slot_count ? cfg->slot_count : BROV_DEFAULT_SLOTS;
    if (slots > BROV_MAX_SLOTS) {
        return UC_ERR_ARG;
    }

    size = cfg->reserve_size ? cfg->reserve_size
                             : (BROV_RESERVE_HEADER_SIZE + (1024ull * 1024ull * 1024ull));
    size = (size + 0xffffull) & ~0xffffull;
    if (size <= BROV_RESERVE_HEADER_SIZE) {
        return UC_ERR_ARG;
    }

    if (!brov_reserve_somewhere(cfg->reserve_base, size, &got)) {
        return UC_ERR_NOMEM;
    }

    if (!brov_os_commit_rw(got, BROV_RESERVE_HEADER_SIZE)) {
        brov_os_release(got, size);
        return UC_ERR_NOMEM;
    }
    memset(got, 0, BROV_RESERVE_HEADER_SIZE);

    g_brov.base = (uint8_t *)got;
    g_brov.size = size;
    g_brov.slot_count = slots;
    g_brov.arena = g_brov.base + BROV_SLOT_AREA_SIZE;
    g_brov.arena_used = 0;
    g_brov.cache_requested = (cfg->flags & BROV_CFG_ENABLE_CACHE) != 0;
    g_brov.strict_audit = (cfg->flags & BROV_CFG_STRICT_AUDIT) != 0;
    g_brov.active = true;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err brov_reservation_info(uint64_t *base, uint64_t *size)
{
    if (!brov_reservation(base, size, NULL)) {
        return UC_ERR_RESOURCE;
    }
    return UC_ERR_OK;
}

/* Lets the caller learn which base a blob needs without duplicating the header
 * layout outside this file. */
UNICORN_EXPORT
uc_err brov_blob_reservation(const void *blob, size_t len, uint64_t *base, uint64_t *size)
{
    const brov_blob_header_t *h = (const brov_blob_header_t *)blob;

    if (!blob || len < sizeof(brov_blob_header_t) || !base || !size) {
        return UC_ERR_ARG;
    }
    if (h->magic != BROV_BLOB_MAGIC || h->abi != BROV_ABI_VERSION) {
        return UC_ERR_ARG;
    }
    *base = h->reservation_base;
    *size = h->reservation_size;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err brov_last_reason(uc_engine *uc, uint32_t *reason)
{
    if (!uc || !reason) {
        return UC_ERR_ARG;
    }
    *reason = uc->brov_last_reason;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err brov_cc_info(uc_engine *uc, brov_cc_info_t *out)
{
    uc_err err;

    if (!uc || !out || out->struct_size != sizeof(brov_cc_info_t)) {
        return UC_ERR_ARG;
    }

    UC_INIT(uc);
    err = uc->brov.info ? (uc_err)uc->brov.info(uc, out) : UC_ERR_RESOURCE;
    restore_jit_state(uc);
    return err;
}

UNICORN_EXPORT
uc_err brov_cc_validate(uc_engine *uc, brov_audit_result_t *out)
{
    uc_err err;

    if (!uc || !out || out->struct_size != sizeof(brov_audit_result_t)) {
        return UC_ERR_ARG;
    }

    UC_INIT(uc);
    err = uc->brov.audit ? (uc_err)uc->brov.audit(uc, out) : UC_ERR_RESOURCE;
    restore_jit_state(uc);
    return err;
}

UNICORN_EXPORT
uc_err brov_cc_save(uc_engine *uc, void **blob, size_t *len)
{
    uc_err err;

    if (!uc || !blob || !len) {
        return UC_ERR_ARG;
    }

    UC_INIT(uc);
    err = uc->brov.save ? (uc_err)uc->brov.save(uc, blob, len) : UC_ERR_RESOURCE;
    restore_jit_state(uc);
    return err;
}

UNICORN_EXPORT
uc_err brov_cc_load(uc_engine *uc, const void *blob, size_t len)
{
    uc_err err;

    if (!uc || !blob) {
        return UC_ERR_ARG;
    }

    UC_INIT(uc);
    err = uc->brov.load ? (uc_err)uc->brov.load(uc, blob, len) : UC_ERR_RESOURCE;
    restore_jit_state(uc);
    return err;
}

/* Retries blocks the load could not verify because their pages were not mapped
 * yet. Cheap and idempotent; call it periodically while remaining is non-zero. */
UNICORN_EXPORT
uc_err brov_cc_resolve(uc_engine *uc, uint32_t *resolved, uint32_t *remaining)
{
    uc_err err;

    if (!uc) {
        return UC_ERR_HANDLE;
    }

    UC_INIT(uc);
    err = uc->brov.resolve ? (uc_err)uc->brov.resolve(uc, resolved, remaining) : UC_ERR_RESOURCE;
    restore_jit_state(uc);
    return err;
}

UNICORN_EXPORT
uc_err brov_cc_free(void *blob)
{
    free(blob);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err brov_reg_ptr(uc_engine *uc, int regid, void **ptr, size_t *size, uint32_t *flags)
{
    uc_err err;

    if (!uc || !ptr || !size || !flags) {
        return UC_ERR_ARG;
    }

    UC_INIT(uc);
    err = uc->brov.reg_ptr ? (uc_err)uc->brov.reg_ptr(uc, regid, ptr, size, flags) : UC_ERR_RESOURCE;
    restore_jit_state(uc);
    return err;
}
