/* Appended to uc.c after brovan_backing_file.inc.c. Window base + A is a second view of the backing file page at guest
 * address A. A window page never allows more than the TLB fast path: no read without UC_PROT_READ, no write without
 * UC_PROT_WRITE, no write to an executable region or to a host page with translated code, and never execute. */

#if defined(__linux__) && BROV_HOST_HAS_DIRECT_EMITTER

#include <signal.h>

#if defined(__aarch64__)
#include "brovan_direct_site_arm64.inc.h"
#endif

/* A change here changes BROV_ABI_VERSION, because a blob with another mask would run past the guard. */
#define BROV_WINDOW_BITS 37
#define BROV_WINDOW_SIZE (1ull << BROV_WINDOW_BITS)
#define BROV_WINDOW_GUARD 0x10000ull
#define BROV_WINDOW_PAGE 0x1000ull

#define BROV_WINDOW_RECOUNT 4096
#define BROV_WINDOW_HOST_HEADROOM 8192
#define BROV_WINDOW_PATCH_AFTER 8

static struct {
    uint8_t *base;
    uint32_t mapping_budget;
    uint32_t since_recount;
    bool closed;
    bool flushed_after_close;
    bool code_has_sites;
    const char *close_reason;
    /* Pages narrowed for translated code. Narrowings the set has no room for go into [lost_lo, lost_hi), where every
     * promotion widens. */
    uint64_t *narrowed_pages;
    uint32_t narrowed_mask;
    uint32_t narrowed_count;
    bool sweep_spent;
    uint64_t lost_lo;
    uint64_t lost_hi;
    uintptr_t *site_pc;
    uint8_t *site_hits;
    uint32_t site_mask;
    uint64_t views;
    uint64_t narrowed;
    uint64_t widened;
    uint64_t faults;
    uint64_t patches;
} g_brov_window;

static uint32_t brov_window_read_count(const char *path, bool lines)
{
    char buf[4096];
    uint64_t count = 0;
    ssize_t got;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        return 0;
    }
    while ((got = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t i;

        for (i = 0; i < got; i++) {
            if (lines) {
                count += buf[i] == 0x0a;
            } else if (buf[i] >= '0' && buf[i] <= '9') {
                count = count * 10 + (uint64_t)(buf[i] - '0');
            }
        }
    }
    close(fd);
    return count > UINT32_MAX ? UINT32_MAX : (uint32_t)count;
}

static uint32_t brov_window_pow2(uint32_t n)
{
    return (uint32_t)pow2floor(n < 64 ? 64 : n > (1u << 24) ? (1u << 24) : n);
}

static void brov_window_release(void)
{
    if (g_brov_window.base) {
        munmap(g_brov_window.base, (size_t)(BROV_WINDOW_SIZE + BROV_WINDOW_GUARD));
        g_brov_window.base = NULL;
    }
    free(g_brov_window.narrowed_pages);
    free(g_brov_window.site_pc);
    free(g_brov_window.site_hits);
    g_brov_window.narrowed_pages = NULL;
    g_brov_window.site_pc = NULL;
    g_brov_window.site_hits = NULL;
}

static bool brov_window_reserve(uint32_t mapping_budget, uint32_t sites, uint32_t narrowed_pages)
{
    uint32_t host_limit = brov_window_read_count("/proc/sys/vm/max_map_count", false);
    void *p;

    if (host_limit != 0) {
        if (host_limit <= BROV_WINDOW_HOST_HEADROOM) {
            return false;
        }
        if (host_limit - BROV_WINDOW_HOST_HEADROOM < mapping_budget) {
            mapping_budget = host_limit - BROV_WINDOW_HOST_HEADROOM;
        }
    }
    p = mmap(NULL, (size_t)(BROV_WINDOW_SIZE + BROV_WINDOW_GUARD), PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        return false;
    }
    g_brov_window.base = (uint8_t *)p;
    g_brov_window.mapping_budget = mapping_budget;
    g_brov_window.narrowed_mask = brov_window_pow2(narrowed_pages) - 1;
    g_brov_window.site_mask = brov_window_pow2(sites) - 1;
    g_brov_window.narrowed_pages = calloc((size_t)g_brov_window.narrowed_mask + 1, sizeof(uint64_t));
    g_brov_window.site_pc = calloc((size_t)g_brov_window.site_mask + 1, sizeof(uintptr_t));
    g_brov_window.site_hits = calloc((size_t)g_brov_window.site_mask + 1, 1);
    if (!g_brov_window.narrowed_pages || !g_brov_window.site_pc || !g_brov_window.site_hits) {
        brov_window_release();
        return false;
    }
    return true;
}

static bool brov_window_open(void)
{
    return g_brov_window.base && !g_brov_window.closed;
}

static bool brov_window_covers(uint64_t guest, uint64_t size)
{
    return guest < BROV_WINDOW_SIZE && size <= BROV_WINDOW_SIZE - guest;
}

static bool brov_window_backs(uint64_t guest, uint64_t size, const void *host)
{
    return brov_window_open() && brov_window_covers(guest, size) && brov_backing_owns(host, size);
}

static void brov_window_close(const char *why)
{
    if (g_brov_window.closed) {
        return;
    }
    g_brov_window.closed = true;
    g_brov_window.close_reason = why;
    if (mmap(g_brov_window.base, (size_t)BROV_WINDOW_SIZE, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0) == MAP_FAILED) {
        fprintf(stderr, "[brovan] direct window: no-access remap failed, errno %d\n", errno);
        abort();
    }
}

/* Views and protection runs split the reservation into host mappings, and the host limits mappings per process. */
static void brov_window_count(uint32_t added)
{
    uint32_t mappings;

    g_brov_window.since_recount += added;
    if (g_brov_window.since_recount < BROV_WINDOW_RECOUNT) {
        return;
    }
    g_brov_window.since_recount = 0;
    mappings = brov_window_read_count("/proc/self/maps", true);
    if (mappings == 0 || mappings > g_brov_window.mapping_budget) {
        brov_window_close("mapping budget");
    }
}

static int brov_window_prot(uint32_t perms)
{
    if ((perms & UC_PROT_READ) == 0) {
        return PROT_NONE;
    }
    if ((perms & UC_PROT_WRITE) != 0 && (perms & UC_PROT_EXEC) == 0) {
        return PROT_READ | PROT_WRITE;
    }
    return PROT_READ;
}

static uint32_t brov_window_hash(uint64_t key, uint32_t mask)
{
    return (uint32_t)((key * 0x9e3779b97f4a7c15ull) >> 40) & mask;
}

static bool brov_window_lost(uint64_t guest)
{
    return guest >= g_brov_window.lost_lo && guest < g_brov_window.lost_hi;
}

static uint32_t brov_window_mark_limit(void)
{
    return (g_brov_window.narrowed_mask + 1) / 4 * 3;
}

static uint32_t brov_window_slot(uint64_t key)
{
    uint32_t i = brov_window_hash(key, g_brov_window.narrowed_mask);

    while (g_brov_window.narrowed_pages[i] != 0 && g_brov_window.narrowed_pages[i] != key) {
        i = (i + 1) & g_brov_window.narrowed_mask;
    }
    return i;
}

static void brov_window_unmark_slot(uint32_t i);

/* A mark matters only while a promotion can still widen its page, so only in a writable region in the file. */
static bool brov_window_mark_live(struct uc_struct *uc, uint64_t key)
{
    uint64_t page = (key - 1) * BROV_WINDOW_PAGE;
    MemoryRegion *mr = uc->memory_mapping(uc, page);

    return mr && mr->ram_block && (brov_window_prot(mr->perms) & PROT_WRITE) != 0 &&
           brov_backing_owns(mr->ram_block->host + (page - mr->addr), BROV_WINDOW_PAGE);
}

/* Runs only when the set is full, so the map paths never search it for marks of pages that went away. */
static void brov_window_sweep(struct uc_struct *uc)
{
    uint32_t i;

    for (i = 0; i <= g_brov_window.narrowed_mask;) {
        uint64_t key = g_brov_window.narrowed_pages[i];

        if (key != 0 && !brov_window_mark_live(uc, key)) {
            brov_window_unmark_slot(i);
        } else {
            i++;
        }
    }
}

static void brov_window_mark(struct uc_struct *uc, uint64_t guest)
{
    uint64_t key = guest / BROV_WINDOW_PAGE + 1;
    uint32_t i = brov_window_slot(key);

    if (g_brov_window.narrowed_pages[i] == key) {
        return;
    }
    if (g_brov_window.narrowed_count >= brov_window_mark_limit() && !g_brov_window.sweep_spent) {
        g_brov_window.sweep_spent = true;
        brov_window_sweep(uc);
        i = brov_window_slot(key);
    }
    if (g_brov_window.narrowed_count >= brov_window_mark_limit()) {
        if (g_brov_window.lost_lo >= g_brov_window.lost_hi) {
            g_brov_window.lost_lo = guest;
            g_brov_window.lost_hi = guest + BROV_WINDOW_PAGE;
        } else {
            g_brov_window.lost_lo = MIN(g_brov_window.lost_lo, guest);
            g_brov_window.lost_hi = MAX(g_brov_window.lost_hi, guest + BROV_WINDOW_PAGE);
        }
        return;
    }
    g_brov_window.narrowed_pages[i] = key;
    g_brov_window.narrowed_count++;
}

static int64_t brov_window_find(uint64_t guest)
{
    uint64_t key = guest / BROV_WINDOW_PAGE + 1;
    uint32_t i = brov_window_hash(key, g_brov_window.narrowed_mask);

    while (g_brov_window.narrowed_pages[i] != key) {
        if (g_brov_window.narrowed_pages[i] == 0) {
            return -1;
        }
        i = (i + 1) & g_brov_window.narrowed_mask;
    }
    return i;
}

/* Linear probing, so the later entries of the run move back over the freed slot. */
static void brov_window_unmark_slot(uint32_t i)
{
    uint32_t j = i;

    for (;;) {
        uint32_t home;

        g_brov_window.narrowed_pages[i] = 0;
        do {
            j = (j + 1) & g_brov_window.narrowed_mask;
            if (g_brov_window.narrowed_pages[j] == 0) {
                if (--g_brov_window.narrowed_count < brov_window_mark_limit() / 2) {
                    g_brov_window.sweep_spent = false;
                }
                return;
            }
            home = brov_window_hash(g_brov_window.narrowed_pages[j], g_brov_window.narrowed_mask);
        } while (i <= j ? (i < home && home <= j) : (i < home || home <= j));
        g_brov_window.narrowed_pages[i] = g_brov_window.narrowed_pages[j];
        i = j;
    }
}

/* True when the page may be narrower than its region allows. */
static bool brov_window_take(uint64_t guest)
{
    int64_t slot = brov_window_find(guest);

    if (slot >= 0) {
        brov_window_unmark_slot((uint32_t)slot);
        return true;
    }
    return brov_window_lost(guest);
}

/* A view, an unview or a protection run sets every page of the range, so none of it stays lost. */
static void brov_window_forget_lost(uint64_t guest, uint64_t size)
{
    uint64_t end = guest + size;

    if (g_brov_window.lost_lo >= g_brov_window.lost_hi) {
        return;
    }
    if (guest <= g_brov_window.lost_lo && end >= g_brov_window.lost_hi) {
        g_brov_window.lost_lo = g_brov_window.lost_hi = 0;
    } else if (guest <= g_brov_window.lost_lo && end > g_brov_window.lost_lo) {
        g_brov_window.lost_lo = end;
    } else if (guest < g_brov_window.lost_hi && end >= g_brov_window.lost_hi) {
        g_brov_window.lost_hi = guest;
    }
}

static void brov_window_set(uint64_t guest, uint64_t size, int prot, const char *what)
{
    if (mprotect(g_brov_window.base + guest, (size_t)size, prot) != 0) {
        if (prot == PROT_READ || prot == PROT_NONE) {
            brov_window_close(what);
        }
        return;
    }
    brov_window_count(2);
}

static void brov_window_narrow_page(struct uc_struct *uc, uint64_t guest, int prot, const char *what)
{
    brov_window_set(guest, BROV_WINDOW_PAGE, prot, what);
    brov_window_mark(uc, guest);
    g_brov_window.narrowed++;
}

/* A store through one mapping of a host page must invalidate the blocks of the others, so a new or reset mapping
 * narrows the pages whose host page already holds blocks through another mapping. */
static void brov_window_narrow_alias_code(struct uc_struct *uc, uint64_t guest, uint64_t size, const void *host)
{
    uintptr_t start = (uintptr_t)host;
    uint32_t i;

    for (i = 0; i < uc->brov_alias_count && brov_window_open(); i++) {
        const brov_alias_range *alias = &uc->brov_aliases[i];
        uintptr_t lo = MAX(start, alias->host);
        uintptr_t hi = MIN(start + size, alias->host + alias->size);
        uint64_t other = alias->guest + (lo - alias->host);
        uint64_t other_end = other + (hi - lo);

        if (lo >= hi || alias->guest - guest == alias->host - start) {
            continue;
        }
        while (other < other_end) {
            MemoryRegion *mr = uc->memory_mapping(uc, other);
            uint64_t stop = mr && mr->end > other ? MIN((uint64_t)mr->end, other_end) : other + BROV_WINDOW_PAGE;

            if (mr && mr->ram_block && mr->brov_was_exec) {
                for (; other < stop; other += BROV_WINDOW_PAGE) {
                    if (uc->brov.page_has_tbs(uc, mr->ram_block->offset + (other - mr->addr))) {
                        brov_window_narrow_page(uc, guest + (alias->host + (other - alias->guest) - start), PROT_READ,
                                                "alias code page");
                    }
                }
            }
            other = stop;
        }
    }
}

void brov_window_view(struct uc_struct *uc, uint64_t guest, uint64_t size, void *host, uint32_t perms)
{
    int prot = brov_window_prot(perms);
    uint64_t offset;

    if (((guest | size) & (BROV_WINDOW_PAGE - 1)) != 0 || !brov_window_backs(guest, size, host)) {
        return;
    }
    offset = (uint64_t)((const uint8_t *)host - g_brov_backing.home);
    if (mmap(g_brov_window.base + guest, (size_t)size, prot, MAP_SHARED | MAP_FIXED, g_brov_backing.fd,
             (off_t)offset) == MAP_FAILED) {
        brov_window_close("view");
        return;
    }
    brov_window_forget_lost(guest, size);
    g_brov_window.views++;
    brov_window_count(2);
    if ((prot & PROT_WRITE) != 0 && uc->brov_alias_count != 0 && uc->brov.page_has_tbs) {
        brov_window_narrow_alias_code(uc, guest, size, host);
    }
}

void brov_window_unview(struct uc_struct *uc, uint64_t guest, uint64_t size, void *host)
{
    (void)uc;
    if (!brov_window_backs(guest, size, host)) {
        return;
    }
    if (mmap(g_brov_window.base + guest, (size_t)size, PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0) == MAP_FAILED) {
        brov_window_close("unview");
        return;
    }
    brov_window_forget_lost(guest, size);
}

/* A region keeps its translated blocks after it loses EXEC, so their pages stay without write. */
void brov_window_protect(struct uc_struct *uc, uint64_t guest, uint64_t size, void *host, uint64_t ram,
                         uint32_t perms, bool was_exec)
{
    int prot = brov_window_prot(perms);
    uint64_t page;

    if (!brov_window_backs(guest, size, host)) {
        return;
    }
    brov_window_set(guest, size, prot, "protect");
    brov_window_forget_lost(guest, size);
    if ((prot & PROT_WRITE) == 0 || !uc->brov.page_has_tbs) {
        return;
    }
    if (uc->brov_alias_count != 0) {
        brov_window_narrow_alias_code(uc, guest, size, host);
    }
    if (!was_exec) {
        return;
    }
    for (page = 0; page < size && brov_window_open(); page += BROV_WINDOW_PAGE) {
        if (uc->brov.page_has_tbs(uc, ram + page)) {
            brov_window_narrow_page(uc, guest + page, PROT_READ, "code page");
        }
    }
}

/* guest is another mapping of a host page that now holds translated code. */
void brov_window_narrow(struct uc_struct *uc, uint64_t guest, void *host)
{
    MemoryRegion *mr;

    guest &= ~(BROV_WINDOW_PAGE - 1);
    if (!brov_window_backs(guest, BROV_WINDOW_PAGE, host)) {
        return;
    }
    mr = uc->memory_mapping(uc, guest);
    if (!mr) {
        return;
    }
    brov_window_narrow_page(uc, guest, brov_window_prot(mr->perms) & PROT_READ, "alias code page");
}

/* A store was promoted onto the TLB fast path, so the page holds no translated code. */
void brov_window_widen(struct uc_struct *uc, uint64_t guest, void *host, uint32_t perms)
{
    (void)uc;
    guest &= ~(BROV_WINDOW_PAGE - 1);
    if (!brov_window_backs(guest, BROV_WINDOW_PAGE, host) || !brov_window_take(guest)) {
        return;
    }
    brov_window_set(guest, BROV_WINDOW_PAGE, brov_window_prot(perms), "widen");
    g_brov_window.widened++;
}

static int brov_window_check_mode = -1;

bool brov_window_checking(void)
{
    if (brov_window_check_mode < 0) {
        brov_window_check_mode = getenv("BROVAN_DIRECT_MEM_CHECK") != NULL;
    }
    return brov_window_check_mode != 0;
}

/* A store that the TLB keeps off its fast path must not be writable in the window. */
void brov_window_check_store(struct uc_struct *uc, uint64_t guest, void *host, uint32_t perms)
{
    static uint32_t reported;
    uint64_t page = guest & ~(BROV_WINDOW_PAGE - 1);
    const uint8_t *host_page = (const uint8_t *)host - (guest - page);

    if (!brov_window_backs(page, BROV_WINDOW_PAGE, host_page) || brov_mem_hook_signature(uc) != 0 ||
        (brov_window_prot(perms) & PROT_WRITE) == 0 ||
        brov_window_find(page) >= 0 || brov_window_lost(page) || reported >= 16) {
        return;
    }
    reported++;
    fprintf(stderr, "[brovan] direct window check: guest page 0x%llx is writable in the window, but its stores need "
                    "the slow path\n", (unsigned long long)page);
}

static struct sigaction brov_window_prev_segv;
static struct sigaction brov_window_prev_bus;
static bool brov_window_handler_installed;

uint64_t brov_window_emit_mask(void)
{
    if (!brov_window_open() || !brov_reservation(NULL, NULL, NULL)) {
        return 0;
    }
    return BROV_WINDOW_SIZE - 1;
}

void brov_window_note_site(void)
{
    g_brov_window.code_has_sites = true;
}

/* Once any block held a direct site, every blob of this process may hold one. */
bool brov_window_code_has_sites(void)
{
    return g_brov_window.code_has_sites;
}

bool brov_window_reserved(void)
{
    return g_brov_window.base != NULL;
}

/* A flush gives the code buffer to new blocks, which must not inherit the fault counts of old sites. */
void brov_window_forget_sites(void)
{
    if (g_brov_window.site_pc) {
        memset(g_brov_window.site_pc, 0, ((size_t)g_brov_window.site_mask + 1) * sizeof(uintptr_t));
    }
}

/* A site that keeps faulting branches to its probe for good, because an access outside the file or to MMIO always
 * faults. */
static void brov_window_count_site(uintptr_t pc)
{
    uint32_t i = brov_window_hash((uint64_t)(pc >> 2), g_brov_window.site_mask);

    g_brov_window.faults++;
    if (g_brov_window.site_pc[i] != pc) {
        g_brov_window.site_pc[i] = pc;
        g_brov_window.site_hits[i] = 0;
    }
    if (++g_brov_window.site_hits[i] >= BROV_WINDOW_PATCH_AFTER) {
        brov_direct_site_patch(pc);
        g_brov_window.site_pc[i] = 0;
        g_brov_window.patches++;
    }
}

static void brov_window_chain(int sig, siginfo_t *si, void *ctx)
{
    const struct sigaction *prev = sig == SIGBUS ? &brov_window_prev_bus : &brov_window_prev_segv;

    if ((prev->sa_flags & SA_SIGINFO) != 0 && prev->sa_sigaction) {
        prev->sa_sigaction(sig, si, ctx);
    } else if (prev->sa_handler != SIG_DFL && prev->sa_handler != SIG_IGN) {
        prev->sa_handler(sig);
    } else {
        /* The faulting instruction runs again and the default action ends the process. */
        signal(sig, SIG_DFL);
    }
}

static void brov_window_on_fault(int sig, siginfo_t *si, void *ctx)
{
    uintptr_t pc = brov_direct_fault_pc(ctx);
    uint8_t *addr = (uint8_t *)si->si_addr;
    uint64_t code_base;
    uint64_t code_size;

    if (g_brov_window.base && addr >= g_brov_window.base &&
        addr < g_brov_window.base + BROV_WINDOW_SIZE + BROV_WINDOW_GUARD &&
        brov_reservation(&code_base, &code_size, NULL) &&
        brov_direct_site_at(pc, (uintptr_t)code_base, (uintptr_t)(code_base + code_size))) {
        brov_window_count_site(pc);
        brov_direct_set_fault_pc(ctx, brov_direct_site_probe(pc));
        return;
    }
    brov_window_chain(sig, si, ctx);
}

/* Unicorn creates the CPU lazily, so the base is set at every uc_emu_start. A closed window stays reserved with no
 * access, and one flush stops the old sites from faulting. */
void brov_window_bind(struct uc_struct *uc)
{
    if (!g_brov_window.base || !uc->brov.set_window_base) {
        return;
    }
    uc->brov.set_window_base(uc, (uint64_t)(uintptr_t)g_brov_window.base);
    if (g_brov_window.closed && !g_brov_window.flushed_after_close) {
        g_brov_window.flushed_after_close = true;
        uc->tb_flush(uc);
    }
}

/* A fault that is not at a direct site goes on to the SIGSEGV or SIGBUS handler installed before. */
UNICORN_EXPORT
uc_err brov_window_attach(void)
{
    struct sigaction sa;

    if (!brov_window_open()) {
        return UC_ERR_RESOURCE;
    }
    pthread_mutex_lock(&g_brov_backing.lock);
    if (!brov_window_handler_installed) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = brov_window_on_fault;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGSEGV, NULL, &brov_window_prev_segv) != 0 ||
            sigaction(SIGBUS, NULL, &brov_window_prev_bus) != 0 || sigaction(SIGSEGV, &sa, NULL) != 0 ||
            sigaction(SIGBUS, &sa, NULL) != 0) {
            pthread_mutex_unlock(&g_brov_backing.lock);
            brov_window_close("fault handler");
            return UC_ERR_RESOURCE;
        }
        brov_window_handler_installed = true;
    }
    pthread_mutex_unlock(&g_brov_backing.lock);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err brov_window_stats(uint64_t *counts, const char **close_reason)
{
    if (!counts || !close_reason || !g_brov_window.base) {
        return UC_ERR_RESOURCE;
    }
    counts[0] = g_brov_window.views;
    counts[1] = g_brov_window.narrowed;
    counts[2] = g_brov_window.widened;
    counts[3] = g_brov_window.faults;
    counts[4] = g_brov_window.patches;
    *close_reason = g_brov_window.close_reason;
    return UC_ERR_OK;
}

#else

uint64_t brov_window_emit_mask(void)
{
    return 0;
}

void brov_window_note_site(void)
{
}

bool brov_window_code_has_sites(void)
{
    return false;
}

bool brov_window_reserved(void)
{
    return false;
}

void brov_window_forget_sites(void)
{
}

bool brov_window_checking(void)
{
    return false;
}

void brov_window_check_store(struct uc_struct *uc, uint64_t guest, void *host, uint32_t perms)
{
    (void)uc;
    (void)guest;
    (void)host;
    (void)perms;
}

void brov_window_bind(struct uc_struct *uc)
{
    (void)uc;
}

UNICORN_EXPORT
uc_err brov_window_attach(void)
{
    return UC_ERR_RESOURCE;
}

UNICORN_EXPORT
uc_err brov_window_stats(uint64_t *counts, const char **close_reason)
{
    (void)counts;
    (void)close_reason;
    return UC_ERR_RESOURCE;
}

void brov_window_view(struct uc_struct *uc, uint64_t guest, uint64_t size, void *host, uint32_t perms)
{
    (void)uc;
    (void)guest;
    (void)size;
    (void)host;
    (void)perms;
}

void brov_window_unview(struct uc_struct *uc, uint64_t guest, uint64_t size, void *host)
{
    (void)uc;
    (void)guest;
    (void)size;
    (void)host;
}

void brov_window_protect(struct uc_struct *uc, uint64_t guest, uint64_t size, void *host, uint64_t ram,
                         uint32_t perms, bool was_exec)
{
    (void)uc;
    (void)guest;
    (void)size;
    (void)host;
    (void)ram;
    (void)perms;
    (void)was_exec;
}

void brov_window_narrow(struct uc_struct *uc, uint64_t guest, void *host)
{
    (void)uc;
    (void)guest;
    (void)host;
}

void brov_window_widen(struct uc_struct *uc, uint64_t guest, void *host, uint32_t perms)
{
    (void)uc;
    (void)guest;
    (void)host;
    (void)perms;
}

#endif
