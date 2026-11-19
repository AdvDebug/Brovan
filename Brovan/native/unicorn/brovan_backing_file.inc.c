/* Appended to uc.c. One memfd per process holds the host memory of guest blocks. A freed range is punched, so it
 * reads zero when it is given out again. */

#if defined(__linux__) && BROV_HOST_HAS_DIRECT_EMITTER

#include <linux/falloc.h>
#include <pthread.h>
#include <sys/syscall.h>

typedef struct {
    uint64_t start;
    uint64_t size;
} brov_backing_range;

static struct {
    pthread_mutex_t lock;
    int fd;
    uint8_t *home;
    uint64_t size;
    uint64_t top;
    brov_backing_range *free;
    uint32_t free_count;
    uint32_t free_cap;
} g_brov_backing = { PTHREAD_MUTEX_INITIALIZER, -1 };

static bool brov_window_reserve(uint32_t mapping_budget, uint32_t sites, uint32_t narrowed_pages);
static void brov_window_release(void);

static uint64_t brov_backing_round(uint64_t size)
{
    return QEMU_ALIGN_UP(size, 0x1000ull);
}

static bool brov_backing_owns(const void *ptr, uint64_t size)
{
    const uint8_t *p = (const uint8_t *)ptr;

    return g_brov_backing.home && p >= g_brov_backing.home &&
           (uint64_t)(p - g_brov_backing.home) <= g_brov_backing.size &&
           size <= g_brov_backing.size - (uint64_t)(p - g_brov_backing.home);
}

static bool brov_backing_offset(const void *ptr, uint64_t size, uint64_t *offset)
{
    if (!brov_backing_owns(ptr, size)) {
        return false;
    }
    *offset = (uint64_t)((const uint8_t *)ptr - g_brov_backing.home);
    return true;
}

static bool brov_backing_punch(uint64_t offset, uint64_t size)
{
    if (syscall(__NR_fallocate, g_brov_backing.fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, (off_t)offset,
                (off_t)size) == 0 ||
        madvise(g_brov_backing.home + offset, (size_t)size, MADV_REMOVE) == 0) {
        return true;
    }
    fprintf(stderr, "[brovan] backing file: punch of 0x%llx bytes at 0x%llx failed, errno %d\n",
            (unsigned long long)size, (unsigned long long)offset, errno);
    return false;
}

/* The free list is sorted by start, and no range touches another or ends at top. */
static bool brov_backing_give_back(uint64_t start, uint64_t size)
{
    brov_backing_range *r = g_brov_backing.free;
    uint32_t n = g_brov_backing.free_count;
    uint32_t i = 0;

    if (start + size == g_brov_backing.top) {
        g_brov_backing.top = start;
        if (n > 0 && r[n - 1].start + r[n - 1].size == start) {
            g_brov_backing.top = r[n - 1].start;
            g_brov_backing.free_count = n - 1;
        }
        return true;
    }
    while (i < n && r[i].start < start) {
        i++;
    }
    if (i > 0 && r[i - 1].start + r[i - 1].size == start) {
        i--;
        r[i].size += size;
    } else {
        if (n == g_brov_backing.free_cap) {
            uint32_t cap = n ? n * 2 : 64;
            brov_backing_range *grown = realloc(r, (size_t)cap * sizeof(*r));

            if (!grown) {
                return false;
            }
            g_brov_backing.free = r = grown;
            g_brov_backing.free_cap = cap;
        }
        memmove(&r[i + 1], &r[i], (size_t)(n - i) * sizeof(*r));
        r[i].start = start;
        r[i].size = size;
        g_brov_backing.free_count = ++n;
    }
    if (i + 1 < n && r[i].start + r[i].size == r[i + 1].start) {
        r[i].size += r[i + 1].size;
        memmove(&r[i + 1], &r[i + 2], (size_t)(n - i - 2) * sizeof(*r));
        g_brov_backing.free_count = --n;
    }
    return true;
}

/* The window is reserved before the home view is mapped, so the view cannot take its host range. */
UNICORN_EXPORT
uc_err brov_backing_open(uint64_t size, uint32_t window_mappings, uint32_t window_sites,
                         uint32_t window_narrowed_pages)
{
    uc_err err = UC_ERR_OK;
    int fd;
    void *home;

    size = brov_backing_round(size);
    pthread_mutex_lock(&g_brov_backing.lock);
    if (g_brov_backing.home) {
        goto out;
    }
    if (getenv("BROVAN_NO_DIRECT_MEM") != NULL || size == 0 || sysconf(_SC_PAGESIZE) != 4096 ||
        !brov_window_reserve(window_mappings, window_sites, window_narrowed_pages)) {
        err = UC_ERR_RESOURCE;
        goto out;
    }
    fd = (int)syscall(__NR_memfd_create, "brovan-guest", 1u /* MFD_CLOEXEC */);
    if (fd < 0) {
        err = UC_ERR_RESOURCE;
        goto out;
    }
    if (ftruncate(fd, (off_t)size) != 0) {
        close(fd);
        err = UC_ERR_NOMEM;
        goto out;
    }
    home = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_NORESERVE, fd, 0);
    if (home == MAP_FAILED) {
        close(fd);
        err = UC_ERR_NOMEM;
        goto out;
    }
    g_brov_backing.fd = fd;
    g_brov_backing.home = (uint8_t *)home;
    g_brov_backing.size = size;
out:
    if (err != UC_ERR_OK) {
        brov_window_release();
    }
    pthread_mutex_unlock(&g_brov_backing.lock);
    return err;
}

UNICORN_EXPORT
void *brov_backing_alloc(uint64_t size)
{
    uint8_t *p = NULL;
    uint32_t i;

    size = brov_backing_round(size);
    if (size == 0) {
        return NULL;
    }
    pthread_mutex_lock(&g_brov_backing.lock);
    if (g_brov_backing.home) {
        for (i = 0; i < g_brov_backing.free_count; i++) {
            brov_backing_range *r = &g_brov_backing.free[i];

            if (r->size >= size) {
                p = g_brov_backing.home + r->start;
                r->start += size;
                r->size -= size;
                if (r->size == 0) {
                    memmove(r, r + 1, (size_t)(g_brov_backing.free_count - i - 1) * sizeof(*r));
                    g_brov_backing.free_count--;
                }
                break;
            }
        }
        if (!p && size <= g_brov_backing.size - g_brov_backing.top) {
            p = g_brov_backing.home + g_brov_backing.top;
            g_brov_backing.top += size;
        }
    }
    pthread_mutex_unlock(&g_brov_backing.lock);
    return p;
}

UNICORN_EXPORT
bool brov_backing_free(void *ptr, uint64_t size)
{
    uint64_t offset;

    size = brov_backing_round(size);
    pthread_mutex_lock(&g_brov_backing.lock);
    if (!brov_backing_offset(ptr, size, &offset)) {
        pthread_mutex_unlock(&g_brov_backing.lock);
        return false;
    }
    if (brov_backing_punch(offset, size) && !brov_backing_give_back(offset, size)) {
        fprintf(stderr, "[brovan] backing file: 0x%llx bytes at 0x%llx not reusable, no memory for the free list\n",
                (unsigned long long)size, (unsigned long long)offset);
    }
    pthread_mutex_unlock(&g_brov_backing.lock);
    return true;
}

UNICORN_EXPORT
bool brov_backing_discard(void *ptr, uint64_t size)
{
    uint64_t offset;
    bool owned;

    size = brov_backing_round(size);
    pthread_mutex_lock(&g_brov_backing.lock);
    owned = brov_backing_offset(ptr, size, &offset);
    if (owned) {
        brov_backing_punch(offset, size);
    }
    pthread_mutex_unlock(&g_brov_backing.lock);
    return owned;
}

#else

UNICORN_EXPORT
uc_err brov_backing_open(uint64_t size, uint32_t window_mappings, uint32_t window_sites,
                         uint32_t window_narrowed_pages)
{
    (void)size;
    (void)window_mappings;
    (void)window_sites;
    (void)window_narrowed_pages;
    return UC_ERR_RESOURCE;
}

UNICORN_EXPORT
void *brov_backing_alloc(uint64_t size)
{
    (void)size;
    return NULL;
}

UNICORN_EXPORT
bool brov_backing_free(void *ptr, uint64_t size)
{
    (void)ptr;
    (void)size;
    return false;
}

UNICORN_EXPORT
bool brov_backing_discard(void *ptr, uint64_t size)
{
    (void)ptr;
    (void)size;
    return false;
}

#endif
