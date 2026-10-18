#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#define VK_USE_PLATFORM_WIN32_KHR 1
#include <vulkan/vulkan.h>
#include "obj/generated/brovvulk_gen.h"
#include "obj/generated/brovvulk_gen_protos.h"

#define IOCTL_BROVVULK_GEN 0x80002004u

#if defined(_MSC_VER)
#define BVK_TLS __declspec(thread)
#define BVK_INLINE __forceinline
#else
#define BVK_TLS __thread
#define BVK_INLINE inline __attribute__((always_inline))
#endif

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static HANDLE brov_dev(void)
{
    if (g_dev == INVALID_HANDLE_VALUE)
    {
        g_dev = CreateFileW(L"\\\\.\\BrovVulk",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
    }
    return g_dev;
}

VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceLayerProperties(
    uint32_t* pPropertyCount, VkLayerProperties* pProperties)
{
    (void)pProperties;
    if (pPropertyCount)
        *pPropertyCount = 0;
    return VK_SUCCESS;
}

// Device layers are deprecated, the spec lets a loader report none.
VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateDeviceLayerProperties(
    VkPhysicalDevice physicalDevice, uint32_t* pPropertyCount, VkLayerProperties* pProperties)
{
    (void)physicalDevice;
    (void)pProperties;
    if (pPropertyCount)
        *pPropertyCount = 0;
    return VK_SUCCESS;
}

#define BVK_HDR 8u

static BVK_TLS unsigned char* bvk_rq;
static BVK_TLS unsigned int bvk_rqcap;
static BVK_TLS unsigned int bvk_rqlen;

static int bvk_grow(void** p, uint32_t* cap, uint32_t need, size_t elem, uint32_t first)
{
    if (need <= *cap)
        return 1;
    uint32_t nc = *cap ? *cap : first;
    while (nc < need)
    {
        if (nc > 0x40000000u)
            return 0;
        nc *= 2u;
    }
    void* np = realloc(*p, (size_t)nc * elem);
    if (!np)
        return 0;
    *p = np;
    *cap = nc;
    return 1;
}

static void bvk_rq_grow(unsigned int need)
{
    bvk_grow((void**)&bvk_rq, &bvk_rqcap, need, 1, 8192u);
}

static void bvk_rq_reset(void)
{
    bvk_rq_grow(BVK_HDR);
    bvk_rqlen = BVK_HDR;
}

static void bvk_w_u32(uint32_t v)
{
    bvk_rq_grow(bvk_rqlen + 4);
    memcpy(bvk_rq + bvk_rqlen, &v, 4);
    bvk_rqlen += 4;
}

static void bvk_w_u64(uint64_t v)
{
    bvk_rq_grow(bvk_rqlen + 8);
    memcpy(bvk_rq + bvk_rqlen, &v, 8);
    bvk_rqlen += 8;
}

static void bvk_w_bytes(const void* s, unsigned int len)
{
    bvk_rq_grow(bvk_rqlen + len);
    if (len)
        memcpy(bvk_rq + bvk_rqlen, s, len);
    bvk_rqlen += len;
}

static BVK_INLINE void bvk_w_scalar(const void* field, int nsize, int wsize)
{
    if (nsize >= wsize)
    {
        bvk_w_bytes(field, (unsigned int)wsize);
        return;
    }

    uint64_t wide = 0;
    memcpy(&wide, field, (size_t)nsize);
    bvk_w_bytes(&wide, (unsigned int)wsize);
}

static BVK_INLINE void bvk_r_scalar(void* field, const unsigned char* src, int nsize, int wsize)
{
    memcpy(field, src, (size_t)(nsize < wsize ? nsize : wsize));
}

static BVK_INLINE uint32_t bvk_handle_at(const unsigned char* p, uint32_t k, int nsize)
{
    const unsigned char* e = p + (size_t)k * (size_t)nsize;
    return nsize == 8 ? (uint32_t)(*(const uint64_t*)e) : (uint32_t)(uintptr_t)(*(void* const*)e);
}

static BVK_INLINE void bvk_handle_put(void* p, uint32_t k, int nsize, uint32_t id)
{
    unsigned char* e = (unsigned char*)p + (size_t)k * (size_t)nsize;
    if (nsize == 8)
        *(uint64_t*)e = id;
    else
        *(void**)e = (void*)(uintptr_t)id;
}

static void bvk_post_flush(void);

static int bvk_rq_send(uint32_t cmd, void* out, uint32_t outCap, uint32_t* outLen)
{
    HANDLE h = brov_dev();
    if (h == INVALID_HANDLE_VALUE)
        return VK_ERROR_INITIALIZATION_FAILED;

    bvk_post_flush();

    uint32_t plen = bvk_rqlen - BVK_HDR;
    memcpy(bvk_rq + 0, &cmd, 4);
    memcpy(bvk_rq + 4, &plen, 4);

    DWORD ret = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_BROVVULK_GEN, bvk_rq, bvk_rqlen, out, outCap, &ret, NULL);
    if (!ok || ret < 4)
        return VK_ERROR_INITIALIZATION_FAILED;

    if (ret > outCap)
        return VK_ERROR_OUT_OF_HOST_MEMORY;

    if (outLen)
        *outLen = ret;
    int vkres;
    memcpy(&vkres, out, 4);
    return vkres;
}

typedef struct
{
    uint32_t id;
    uint64_t size;
    void* map;
    void* bounce;
    int mapActive;
} bvk_mem_entry;

static SRWLOCK bvk_mem_lock = SRWLOCK_INIT;
static bvk_mem_entry* bvk_mem_tab;
static unsigned int bvk_mem_count;
static unsigned int bvk_mem_cap;
static uint32_t bvk_hostvis_types;

static void bvk_note_memprops(const VkPhysicalDeviceMemoryProperties* p)
{
    uint32_t bits = 0;
    uint32_t n = p->memoryTypeCount < 32 ? p->memoryTypeCount : 32;
    for (uint32_t i = 0; i < n; i++)
        if (p->memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
            bits |= 1u << i;
    bvk_hostvis_types = bits;
}

static bvk_mem_entry* bvk_mem_find(uint32_t id)
{
    for (unsigned int i = 0; i < bvk_mem_count; i++)
        if (bvk_mem_tab[i].id == id)
            return &bvk_mem_tab[i];
    return NULL;
}

static void bvk_mem_add(uint32_t id, uint64_t size, void* bounce)
{
    AcquireSRWLockExclusive(&bvk_mem_lock);
    if (bvk_mem_count == bvk_mem_cap)
    {
        unsigned int nc = bvk_mem_cap ? bvk_mem_cap * 2u : 64u;
        bvk_mem_entry* nt = (bvk_mem_entry*)realloc(bvk_mem_tab, nc * sizeof(bvk_mem_entry));
        if (!nt)
        {
            ReleaseSRWLockExclusive(&bvk_mem_lock);
            return;
        }
        bvk_mem_tab = nt;
        bvk_mem_cap = nc;
    }
    bvk_mem_tab[bvk_mem_count].id = id;
    bvk_mem_tab[bvk_mem_count].size = size;
    bvk_mem_tab[bvk_mem_count].map = NULL;
    bvk_mem_tab[bvk_mem_count].bounce = bounce;
    bvk_mem_tab[bvk_mem_count].mapActive = 0;
    bvk_mem_count++;
    ReleaseSRWLockExclusive(&bvk_mem_lock);
}

static int bvk_mem_size(uint32_t id, uint64_t* size)
{
    AcquireSRWLockShared(&bvk_mem_lock);
    bvk_mem_entry* e = bvk_mem_find(id);
    if (e)
        *size = e->size;
    ReleaseSRWLockShared(&bvk_mem_lock);
    return e != NULL;
}

static int bvk_mem_mapped(uint32_t id)
{
    AcquireSRWLockShared(&bvk_mem_lock);
    bvk_mem_entry* e = bvk_mem_find(id);
    int mapped = e != NULL && e->mapActive;
    ReleaseSRWLockShared(&bvk_mem_lock);
    return mapped;
}

static void* bvk_mem_bounce(uint32_t id)
{
    AcquireSRWLockShared(&bvk_mem_lock);
    bvk_mem_entry* e = bvk_mem_find(id);
    void* bounce = e ? e->bounce : NULL;
    ReleaseSRWLockShared(&bvk_mem_lock);
    return bounce;
}

static void bvk_mem_setmap(uint32_t id, void* map)
{
    AcquireSRWLockExclusive(&bvk_mem_lock);
    bvk_mem_entry* e = bvk_mem_find(id);
    if (e)
    {
        e->map = map;
        e->mapActive = 1;
    }
    ReleaseSRWLockExclusive(&bvk_mem_lock);
}

static void bvk_mem_clearmap(uint32_t id)
{
    AcquireSRWLockExclusive(&bvk_mem_lock);
    bvk_mem_entry* e = bvk_mem_find(id);
    void* map = NULL;
    if (e)
    {
        map = e->map;
        e->map = NULL;
        e->mapActive = 0;
    }
    ReleaseSRWLockExclusive(&bvk_mem_lock);
    if (map)
        VirtualFree(map, 0, MEM_RELEASE);
}

static void bvk_mem_remove(uint32_t id)
{
    AcquireSRWLockExclusive(&bvk_mem_lock);
    bvk_mem_entry* e = bvk_mem_find(id);
    void* map = NULL;
    void* bounce = NULL;
    if (e)
    {
        map = e->map;
        bounce = e->bounce;
        *e = bvk_mem_tab[--bvk_mem_count];
    }
    ReleaseSRWLockExclusive(&bvk_mem_lock);
    if (map)
        VirtualFree(map, 0, MEM_RELEASE);
    if (bounce)
        VirtualFree(bounce, 0, MEM_RELEASE);
}

#include "obj/generated/brovvulk_structs.h"

static BVK_INLINE uint32_t bvk_arr_len(const BvkM* d, const unsigned char* s)
{
    uint32_t n = *(const uint32_t*)(s + d->lenOffset);
    return d->lenSamples ? (n + 31) / 32 : n;
}

static void bvk_ser_struct(int sid, const unsigned char* s)
{
    const BvkM* mm = bvk_structs[sid];
    int mc = bvk_struct_counts[sid];
    for (int i = 0; i < mc; i++)
    {
        const BvkM* d = &mm[i];
        const unsigned char* fp = s + d->offset;
        switch (d->kind)
        {
        case 0:
            bvk_w_scalar(fp, d->nsize, d->size);
            break;
        case 1:
            bvk_w_u32((uint32_t)(uintptr_t)(*(void* const*)fp));
            break;
        case 2:
            bvk_ser_struct(d->sub, fp);
            break;
        case 3:
        {
            const void* p = *(const void* const*)fp;
            if (p) { bvk_w_u32(1); bvk_ser_struct(d->sub, (const unsigned char*)p); }
            else bvk_w_u32(0);
            break;
        }
        case 4:
        {
            const void* p = *(const void* const*)fp;
            uint32_t n = bvk_arr_len(d, s);
            if (p) { bvk_w_u32(n); for (uint32_t k = 0; k < n; k++) bvk_ser_struct(d->sub, (const unsigned char*)p + (size_t)k * bvk_struct_nsizes[d->sub]); }
            else bvk_w_u32(0);
            break;
        }
        case 5:
        {
            const unsigned char* p = *(const unsigned char* const*)fp;
            uint32_t n = bvk_arr_len(d, s);
            if (p)
            {
                bvk_w_u32(n);
                for (uint32_t k = 0; k < n; k++)
                    bvk_w_u32(bvk_handle_at(p, k, d->nsize));
            }
            else bvk_w_u32(0);
            break;
        }
        case 6:
        {
            const void* p = *(const void* const*)fp;
            uint32_t n = bvk_arr_len(d, s);
            if (p)
            {
                bvk_w_u32(n);
                if (d->nsize == d->size)
                    bvk_w_bytes(p, n * (unsigned int)d->size);
                else
                    for (uint32_t k = 0; k < n; k++)
                        bvk_w_scalar((const unsigned char*)p + (size_t)k * (size_t)d->nsize, d->nsize, d->size);
            }
            else bvk_w_u32(0);
            break;
        }
        case 7:
        {
            const char* p = *(const char* const*)fp;
            if (p) { uint32_t l = (uint32_t)strlen(p) + 1; bvk_w_u32(l); bvk_w_bytes(p, l); }
            else bvk_w_u32(0);
            break;
        }
        case 8:
        {
            const char* const* p = *(const char* const* const*)fp;
            uint32_t n = bvk_arr_len(d, s);
            if (p) { bvk_w_u32(n); for (uint32_t k = 0; k < n; k++) { uint32_t l = (uint32_t)strlen(p[k]) + 1; bvk_w_u32(l); bvk_w_bytes(p[k], l); } }
            else bvk_w_u32(0);
            break;
        }
        case 9:
        {
            const void* pn = *(const void* const*)fp;
            while (pn)
            {
                int psid = bvk_pnext_sid(*(const uint32_t*)pn);
                if (psid >= 0)
                {
                    bvk_w_u32(1);
                    bvk_w_u32((uint32_t)psid);
                    bvk_ser_struct(psid, (const unsigned char*)pn);
                    break;
                }
                pn = *(const void* const*)((const char*)pn + BVK_PNEXT_OFF);
            }
            if (!pn)
                bvk_w_u32(0);
            break;
        }
        case 11:
        {
            const void* p = *(const void* const*)fp;
            uint32_t n = d->nsize == 8
                ? (uint32_t)(*(const uint64_t*)(s + d->lenOffset))
                : *(const uint32_t*)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); bvk_w_bytes(p, n); }
            else bvk_w_u32(0);
            break;
        }
        case 12:
        {
            uint32_t dt = *(const uint32_t*)(s + d->selOffset);
            if (dt < 32 && (d->selMask & (1u << dt)))
            {
                const void* p = *(const void* const*)fp;
                uint32_t n = *(const uint32_t*)(s + d->lenOffset);
                if (p)
                {
                    bvk_w_u32(n);
                    if (d->sub >= 0)
                        for (uint32_t k = 0; k < n; k++)
                            bvk_ser_struct(d->sub, (const unsigned char*)p + (size_t)k * bvk_struct_nsizes[d->sub]);
                    else
                        for (uint32_t k = 0; k < n; k++)
                            bvk_w_u32(bvk_handle_at((const unsigned char*)p, k, d->nsize));
                }
                else bvk_w_u32(0);
            }
            break;
        }
        default:
            break;
        }
    }
}

static unsigned int bvk_deser_body(int sid, unsigned char* dst, const unsigned char* in)
{
    const BvkM* mm = bvk_structs[sid];
    int mc = bvk_struct_counts[sid];
    unsigned int off = 0;
    for (int i = 0; i < mc; i++)
    {
        const BvkM* d = &mm[i];
        switch (d->kind)
        {
        case 0:
            bvk_r_scalar(dst + d->offset, in + off, d->nsize, d->size);
            off += (unsigned int)d->size;
            break;
        case 2:
            off += bvk_deser_body(d->sub, dst + d->offset, in + off);
            break;
        default:
            break;
        }
    }
    return off;
}

#define BVK_BATCH_ID 0xFFFFFFFEu
#define BVK_BATCH_LIMIT 900000u

typedef struct
{
    VkCommandBuffer cb;
    unsigned char* buf;
    unsigned int cap, len, count;
} bvk_rec_slot;

static SRWLOCK bvk_rec_lock = SRWLOCK_INIT;
static bvk_rec_slot* bvk_rec_tab;
static unsigned int bvk_rec_ntab;

static bvk_rec_slot* bvk_rec_slot_for(VkCommandBuffer cb)
{
    bvk_rec_slot* fre = NULL;
    for (unsigned int i = 0; i < bvk_rec_ntab; i++)
    {
        if (bvk_rec_tab[i].cb == cb)
            return &bvk_rec_tab[i];
        if (!fre && bvk_rec_tab[i].cb == VK_NULL_HANDLE)
            fre = &bvk_rec_tab[i];
    }
    if (fre) { fre->cb = cb; return fre; }
    unsigned int ni = bvk_rec_ntab + 8u;
    bvk_rec_slot* nt = (bvk_rec_slot*)realloc(bvk_rec_tab, ni * sizeof(bvk_rec_slot));
    if (!nt)
        return NULL;
    memset(nt + bvk_rec_ntab, 0, 8u * sizeof(bvk_rec_slot));
    bvk_rec_tab = nt;
    bvk_rec_slot* s = &bvk_rec_tab[bvk_rec_ntab];
    s->cb = cb;
    bvk_rec_ntab = ni;
    return s;
}

static int bvk_rec_slot_grow(bvk_rec_slot* s, unsigned int need)
{
    return bvk_grow((void**)&s->buf, &s->cap, need, 1, 65536u);
}

static void bvk_rec_begin(VkCommandBuffer cb)
{
    AcquireSRWLockExclusive(&bvk_rec_lock);
    bvk_rec_slot* s = bvk_rec_slot_for(cb);
    if (s)
    {
        bvk_rec_slot_grow(s, BVK_HDR + 4);
        s->len = BVK_HDR + 4;
        s->count = 0;
    }
    ReleaseSRWLockExclusive(&bvk_rec_lock);
}

static int bvk_slot_send(bvk_rec_slot* s, uint32_t cmd)
{
    uint32_t plen = s->len - BVK_HDR;
    memcpy(s->buf + 0, &cmd, 4);
    memcpy(s->buf + 4, &plen, 4);
    memcpy(s->buf + BVK_HDR, &s->count, 4);
    HANDLE h = brov_dev();
    int r = VK_ERROR_INITIALIZATION_FAILED;
    if (h != INVALID_HANDLE_VALUE)
    {
        unsigned char obuf[32];
        DWORD ret = 0;
        BOOL ok = DeviceIoControl(h, IOCTL_BROVVULK_GEN, s->buf, s->len, obuf, sizeof(obuf), &ret, NULL);
        if (ok && ret >= 4)
            memcpy(&r, obuf, 4);
    }
    s->len = BVK_HDR + 4;
    s->count = 0;
    return r;
}

// A posted sub-command carries its length, so the host can step over one that fails.
static int bvk_slot_put(bvk_rec_slot* s, uint32_t id, int withLength)
{
    unsigned int args = bvk_rqlen - BVK_HDR;
    if (!bvk_rec_slot_grow(s, s->len + 4 + (withLength ? 4 : 0) + args))
        return 0;
    memcpy(s->buf + s->len, &id, 4);
    s->len += 4;
    if (withLength)
    {
        memcpy(s->buf + s->len, &args, 4);
        s->len += 4;
    }
    memcpy(s->buf + s->len, bvk_rq + BVK_HDR, args);
    s->len += args;
    s->count++;
    return 1;
}

static SRWLOCK bvk_post_lock = SRWLOCK_INIT;
static bvk_rec_slot bvk_posted;
static int bvk_post_off = -1;

static int bvk_env_flag(const char* name, int* cached)
{
    if (*cached < 0)
    {
        char v[4];
        DWORD n = GetEnvironmentVariableA(name, v, sizeof(v));
        *cached = n == 1 && v[0] == '1';
    }
    return *cached;
}

static int bvk_post_disabled(void)
{
    return bvk_env_flag("BROVVULK_NO_POST", &bvk_post_off);
}

// The lock stays held until the posted batch returns, so no ioctl reaches the host ahead of earlier posted work.
static void bvk_post_flush(void)
{
    AcquireSRWLockExclusive(&bvk_post_lock);
    if (bvk_posted.count != 0)
        bvk_slot_send(&bvk_posted, BVK_POSTED_ID);
    ReleaseSRWLockExclusive(&bvk_post_lock);
}

static int bvk_post(uint32_t id)
{
    if (bvk_post_disabled())
        return 0;

    AcquireSRWLockExclusive(&bvk_post_lock);
    if (bvk_posted.len < BVK_HDR + 4 && bvk_rec_slot_grow(&bvk_posted, BVK_HDR + 4))
    {
        bvk_posted.len = BVK_HDR + 4;
        bvk_posted.count = 0;
    }
    unsigned int args = bvk_rqlen - BVK_HDR;
    if (bvk_posted.count != 0 && (uint64_t)bvk_posted.len + 8 + args > BVK_BATCH_LIMIT)
        bvk_slot_send(&bvk_posted, BVK_POSTED_ID);
    int posted = bvk_posted.len >= BVK_HDR + 4 && bvk_slot_put(&bvk_posted, id, 1);
    ReleaseSRWLockExclusive(&bvk_post_lock);
    return posted;
}

static int bvk_rec_dispatch_slot(bvk_rec_slot* s)
{
    bvk_post_flush();
    return bvk_slot_send(s, BVK_BATCH_ID);
}

static void bvk_rec_append(VkCommandBuffer cb, uint32_t id)
{
    AcquireSRWLockExclusive(&bvk_rec_lock);
    bvk_rec_slot* s = bvk_rec_slot_for(cb);
    if (s)
    {
        unsigned int args = bvk_rqlen - BVK_HDR;
        if (s->count != 0 && (uint64_t)s->len + 4 + args > BVK_BATCH_LIMIT)
            bvk_rec_dispatch_slot(s);
        bvk_slot_put(s, id, 0);
    }
    ReleaseSRWLockExclusive(&bvk_rec_lock);
}

static int bvk_rec_flush(VkCommandBuffer cb)
{
    AcquireSRWLockExclusive(&bvk_rec_lock);
    bvk_rec_slot* s = bvk_rec_slot_for(cb);
    int r = VK_SUCCESS;
    if (s)
    {
        r = bvk_rec_dispatch_slot(s);
        s->cb = VK_NULL_HANDLE;
    }
    ReleaseSRWLockExclusive(&bvk_rec_lock);
    return r;
}

typedef struct
{
    uint32_t* keys;
    void** vals;
    uint32_t cap, n, reserved;
} bvk_map;

static uint32_t bvk_map_slot(const bvk_map* m, uint32_t key)
{
    return (key * 2654435761u) & (m->cap - 1);
}

static void* bvk_map_get(const bvk_map* m, uint32_t key)
{
    if (!m->cap || !key)
        return NULL;
    for (uint32_t i = bvk_map_slot(m, key);; i = (i + 1) & (m->cap - 1))
    {
        if (m->keys[i] == key)
            return m->vals[i];
        if (!m->keys[i])
            return NULL;
    }
}

static void bvk_map_insert(bvk_map* m, uint32_t key, void* val)
{
    uint32_t i = bvk_map_slot(m, key);
    while (m->keys[i] && m->keys[i] != key)
        i = (i + 1) & (m->cap - 1);
    if (!m->keys[i])
        m->n++;
    m->keys[i] = key;
    m->vals[i] = val;
}

static int bvk_map_grow(bvk_map* m)
{
    if ((m->n + m->reserved + 1) * 2 <= m->cap)
        return 1;
    bvk_map old = *m;
    uint32_t nc = old.cap ? old.cap * 2u : 64u;
    uint32_t* nk = (uint32_t*)calloc(nc, sizeof(uint32_t));
    void** nv = (void**)calloc(nc, sizeof(void*));
    if (!nk || !nv)
    {
        free(nk);
        free(nv);
        return 0;
    }
    m->keys = nk;
    m->vals = nv;
    m->cap = nc;
    m->n = 0;
    for (uint32_t i = 0; i < old.cap; i++)
    {
        if (old.keys[i])
            bvk_map_insert(m, old.keys[i], old.vals[i]);
    }
    free(old.keys);
    free(old.vals);
    return 1;
}

static int bvk_map_put(bvk_map* m, uint32_t key, void* val)
{
    if (!key || !bvk_map_grow(m))
        return 0;
    bvk_map_insert(m, key, val);
    return 1;
}

static int bvk_map_reserve(bvk_map* m)
{
    if (!bvk_map_grow(m))
        return 0;
    m->reserved++;
    return 1;
}

static void bvk_map_unreserve(bvk_map* m)
{
    m->reserved--;
}

static int bvk_map_put_reserved(bvk_map* m, uint32_t key, void* val)
{
    if (!key)
        return 0;
    m->reserved--;
    bvk_map_insert(m, key, val);
    return 1;
}

static void* bvk_map_del(bvk_map* m, uint32_t key)
{
    if (!m->cap || !key)
        return NULL;
    uint32_t i = bvk_map_slot(m, key);
    while (m->keys[i] != key)
    {
        if (!m->keys[i])
            return NULL;
        i = (i + 1) & (m->cap - 1);
    }
    void* val = m->vals[i];
    m->n--;
    for (uint32_t j = (i + 1) & (m->cap - 1); m->keys[j]; j = (j + 1) & (m->cap - 1))
    {
        uint32_t home = bvk_map_slot(m, m->keys[j]);
        if (((j - home) & (m->cap - 1)) >= ((j - i) & (m->cap - 1)))
        {
            m->keys[i] = m->keys[j];
            m->vals[i] = m->vals[j];
            i = j;
        }
    }
    m->keys[i] = 0;
    m->vals[i] = NULL;
    return val;
}

#define BVK_GUEST_ID_LIMIT 0x7FFFFFF0u
#define BVK_NO_ENTRY 0xFFFFFFFFu

// The guest picks ids from BVK_GUEST_ID_BASE up so that it can post a creation. The host keeps its ids below.
typedef struct
{
    uint32_t parent;
    uint32_t prev, next;
    uint32_t live;
} bvk_id_entry;

typedef struct
{
    uint32_t device;
    uint32_t head;
} bvk_id_chain;

static SRWLOCK bvk_id_lock = SRWLOCK_INIT;
static bvk_id_entry* bvk_ids;
static uint32_t bvk_id_count, bvk_id_cap;
static uint32_t* bvk_id_free;
static uint32_t bvk_id_nfree, bvk_id_freecap;
static bvk_map bvk_id_chains;

static void bvk_id_unlink(uint32_t idx)
{
    bvk_id_entry* e = &bvk_ids[idx];
    if (e->prev != BVK_NO_ENTRY)
        bvk_ids[e->prev].next = e->next;
    else
    {
        bvk_id_chain* c = (bvk_id_chain*)bvk_map_get(&bvk_id_chains, e->parent);
        if (c)
            c->head = e->next;
    }
    if (e->next != BVK_NO_ENTRY)
        bvk_ids[e->next].prev = e->prev;
    e->live = 0;
    bvk_id_free[bvk_id_nfree++] = idx;
}

static int bvk_id_take(uint32_t parent, uint32_t device, uint32_t n, void* handles, int nsize)
{
    uint32_t key = parent ? parent : device;
    bvk_id_chain* c = NULL;
    AcquireSRWLockExclusive(&bvk_id_lock);
    if (key && n <= BVK_GUEST_ID_LIMIT - bvk_id_count + bvk_id_nfree
        && bvk_grow((void**)&bvk_ids, &bvk_id_cap, bvk_id_count + n, sizeof(bvk_id_entry), 256u)
        && bvk_grow((void**)&bvk_id_free, &bvk_id_freecap, bvk_id_count + n, sizeof(uint32_t), 256u))
    {
        c = (bvk_id_chain*)bvk_map_get(&bvk_id_chains, key);
        if (!c && (c = (bvk_id_chain*)malloc(sizeof(bvk_id_chain))) != NULL)
        {
            c->device = device;
            c->head = BVK_NO_ENTRY;
            if (!bvk_map_put(&bvk_id_chains, key, c))
            {
                free(c);
                c = NULL;
            }
        }
    }
    if (c)
    {
        for (uint32_t k = 0; k < n; k++)
        {
            uint32_t idx = bvk_id_nfree != 0 ? bvk_id_free[--bvk_id_nfree] : bvk_id_count++;
            bvk_id_entry* e = &bvk_ids[idx];
            e->parent = key;
            e->prev = BVK_NO_ENTRY;
            e->next = c->head;
            e->live = 1;
            if (c->head != BVK_NO_ENTRY)
                bvk_ids[c->head].prev = idx;
            c->head = idx;
            bvk_handle_put(handles, k, nsize, BVK_GUEST_ID_BASE + idx);
        }
    }
    ReleaseSRWLockExclusive(&bvk_id_lock);
    return c != NULL;
}

static void bvk_id_release_handles(const void* handles, uint32_t n, int nsize)
{
    if (!handles)
        return;
    AcquireSRWLockExclusive(&bvk_id_lock);
    for (uint32_t k = 0; k < n; k++)
    {
        uint32_t id = bvk_handle_at((const unsigned char*)handles, k, nsize);
        if (id < BVK_GUEST_ID_BASE)
            continue;
        uint32_t idx = id - BVK_GUEST_ID_BASE;
        if (idx < bvk_id_count && bvk_ids[idx].live)
            bvk_id_unlink(idx);
    }
    ReleaseSRWLockExclusive(&bvk_id_lock);
}

static void bvk_id_drop_chain(uint32_t key, bvk_id_chain* c)
{
    for (uint32_t idx = c->head; idx != BVK_NO_ENTRY; idx = bvk_ids[idx].next)
    {
        bvk_ids[idx].live = 0;
        bvk_id_free[bvk_id_nfree++] = idx;
    }
    free(bvk_map_del(&bvk_id_chains, key));
}

static void bvk_id_release_parent(uint32_t parent)
{
    AcquireSRWLockExclusive(&bvk_id_lock);
    bvk_id_chain* c = (bvk_id_chain*)bvk_map_get(&bvk_id_chains, parent);
    if (c)
        bvk_id_drop_chain(parent, c);
    ReleaseSRWLockExclusive(&bvk_id_lock);
}

static void bvk_id_release_device(uint32_t device)
{
    AcquireSRWLockExclusive(&bvk_id_lock);
    for (uint32_t i = 0; i < bvk_id_chains.cap; i++)
    {
        uint32_t key = bvk_id_chains.keys[i];
        bvk_id_chain* c = key ? (bvk_id_chain*)bvk_id_chains.vals[i] : NULL;
        if (!c || c->device != device)
            continue;
        bvk_id_drop_chain(key, c);
        i--;
    }
    ReleaseSRWLockExclusive(&bvk_id_lock);
}

#include "obj/generated/brovvulk_gen.c"

// Vulkan does not fail an allocation that fits the totals of a pool made without FREE_DESCRIPTOR_SET_BIT, except
// for lack of memory, so the guest can post such an allocation.
#define BVK_PLAIN_TYPES ((uint32_t)VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT + 1u)
#define BVK_RAISE_FLOOR 4u

typedef struct
{
    VkDevice device;
    uint32_t counts[BVK_PLAIN_TYPES];
} bvk_layout_rec;

typedef struct
{
    VkDevice device;
    int modelable, modeled;
    uint32_t maxSets, sets;
    uint32_t total[BVK_PLAIN_TYPES];
    uint32_t used[BVK_PLAIN_TYPES];
    uint64_t extra;
} bvk_pool_rec;

static SRWLOCK bvk_desc_lock = SRWLOCK_INIT;
static bvk_map bvk_layouts;
static bvk_map bvk_pools;
static uint64_t bvk_raise_left;
static int bvk_raise_ready;
static int bvk_raise_off = -1;

static uint32_t bvk_add_sat(uint32_t a, uint64_t b)
{
    uint64_t s = (uint64_t)a + b;
    return s > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)s;
}

// The shared lock is enough for the pool writes, because Vulkan makes the caller synchronize access to the pool.
static int bvk_desc_account(const VkDescriptorSetAllocateInfo* info, int charge)
{
    uint64_t need[BVK_PLAIN_TYPES] = { 0 };
    int fits = 0;
    AcquireSRWLockShared(&bvk_desc_lock);
    bvk_pool_rec* pool = (bvk_pool_rec*)bvk_map_get(&bvk_pools, (uint32_t)(uintptr_t)info->descriptorPool);
    if (pool && pool->modeled)
    {
        int known = !info->pNext && info->pSetLayouts;
        for (uint32_t k = 0; known && k < info->descriptorSetCount; k++)
        {
            bvk_layout_rec* layout = (bvk_layout_rec*)bvk_map_get(&bvk_layouts, (uint32_t)(uintptr_t)info->pSetLayouts[k]);
            if (!layout)
                known = 0;
            else
                for (uint32_t t = 0; t < BVK_PLAIN_TYPES; t++)
                    need[t] += layout->counts[t];
        }

        fits = known && (uint64_t)pool->sets + info->descriptorSetCount <= pool->maxSets;
        for (uint32_t t = 0; fits && t < BVK_PLAIN_TYPES; t++)
            fits = (uint64_t)pool->used[t] + need[t] <= pool->total[t];

        if (charge && !known)
            pool->modeled = 0;
        else if (charge)
        {
            pool->sets = bvk_add_sat(pool->sets, info->descriptorSetCount);
            for (uint32_t t = 0; t < BVK_PLAIN_TYPES; t++)
                pool->used[t] = bvk_add_sat(pool->used[t], need[t]);
        }
    }
    ReleaseSRWLockShared(&bvk_desc_lock);
    return fits;
}

static int bvk_raise_disabled(void)
{
    return bvk_post_disabled() || bvk_env_flag("BROVVULK_NO_POOL_RAISE", &bvk_raise_off);
}

static void bvk_raise_init(void)
{
    if (bvk_raise_ready)
        return;
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    bvk_raise_left = GlobalMemoryStatusEx(&ms) ? (ms.ullTotalPhys >> 20) * 16u : 0;
    bvk_raise_ready = 1;
}

static uint64_t bvk_desc_extra(const bvk_pool_rec* pool, const uint32_t* count, uint64_t sets, uint64_t limit)
{
    uint64_t extra = 0;
    for (uint32_t t = 0; t < BVK_PLAIN_TYPES; t++)
    {
        uint64_t want = sets * count[t];
        if (want <= pool->total[t])
            continue;
        if (want - pool->total[t] > limit - extra)
            return limit + 1;
        extra += want - pool->total[t];
    }
    return extra;
}

// Vulkan allows an allocation past the pool totals to succeed, so the driver gets totals raised to one set count for
// every type in use. A type sized under one per set gets BVK_RAISE_FLOOR per set for layouts made after the pool.
static uint64_t bvk_desc_raise(VkDevice device, bvk_pool_rec* pool)
{
    uint32_t count[BVK_PLAIN_TYPES] = { 0 };
    for (uint32_t i = 0; i < bvk_layouts.cap; i++)
    {
        bvk_layout_rec* layout = bvk_layouts.keys[i] ? (bvk_layout_rec*)bvk_layouts.vals[i] : NULL;
        for (uint32_t t = 0; layout && layout->device == device && t < BVK_PLAIN_TYPES; t++)
            if (layout->counts[t] > count[t])
                count[t] = layout->counts[t];
    }

    uint64_t have = pool->maxSets;
    for (uint32_t t = 0; t < BVK_PLAIN_TYPES; t++)
    {
        if (!pool->total[t])
            count[t] = 0;
        else if (count[t] && count[t] < BVK_RAISE_FLOOR && pool->total[t] < pool->maxSets)
            count[t] = BVK_RAISE_FLOOR;
        if (count[t] && pool->total[t] / count[t] < have)
            have = pool->total[t] / count[t];
    }

    bvk_raise_init();
    uint64_t lo = have, hi = pool->maxSets;
    while (lo < hi)
    {
        uint64_t mid = lo + (hi - lo + 1) / 2;
        if (bvk_desc_extra(pool, count, mid, bvk_raise_left) <= bvk_raise_left)
            lo = mid;
        else
            hi = mid - 1;
    }
    if (lo <= have)
        return 0;

    uint64_t extra = bvk_desc_extra(pool, count, lo, bvk_raise_left);
    for (uint32_t t = 0; t < BVK_PLAIN_TYPES; t++)
        if (lo * count[t] > pool->total[t])
            pool->total[t] = lo * count[t] > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)(lo * count[t]);
    bvk_raise_left -= extra;
    return extra;
}

static void bvk_desc_drop_device(VkDevice device)
{
    AcquireSRWLockExclusive(&bvk_desc_lock);
    for (uint32_t i = 0; i < bvk_pools.cap; i++)
    {
        uint32_t key = bvk_pools.keys[i];
        bvk_pool_rec* pool = key ? (bvk_pool_rec*)bvk_pools.vals[i] : NULL;
        if (!pool || pool->device != device)
            continue;
        bvk_map_del(&bvk_pools, key);
        bvk_raise_left += pool->extra;
        free(pool);
        i--;
    }
    for (uint32_t i = 0; i < bvk_layouts.cap; i++)
    {
        uint32_t key = bvk_layouts.keys[i];
        bvk_layout_rec* layout = key ? (bvk_layout_rec*)bvk_layouts.vals[i] : NULL;
        if (!layout || layout->device != device)
            continue;
        free(bvk_map_del(&bvk_layouts, key));
        i--;
    }
    ReleaseSRWLockExclusive(&bvk_desc_lock);
}

VKAPI_ATTR VkResult VKAPI_CALL vkCreateDescriptorSetLayout(VkDevice device, const VkDescriptorSetLayoutCreateInfo *pCreateInfo, const VkAllocationCallbacks *pAllocator, VkDescriptorSetLayout *pSetLayout)
{
    VkResult r = bvk_gen_vkCreateDescriptorSetLayout(device, pCreateInfo, pAllocator, pSetLayout);
    if (r < 0 || !pCreateInfo || !pSetLayout || pCreateInfo->pNext || pCreateInfo->flags)
        return r;

    bvk_layout_rec* layout = (bvk_layout_rec*)calloc(1, sizeof(bvk_layout_rec));
    if (!layout)
        return r;
    layout->device = device;
    for (uint32_t i = 0; i < pCreateInfo->bindingCount && pCreateInfo->pBindings; i++)
    {
        const VkDescriptorSetLayoutBinding* b = &pCreateInfo->pBindings[i];
        if ((uint32_t)b->descriptorType >= BVK_PLAIN_TYPES)
        {
            free(layout);
            return r;
        }
        layout->counts[b->descriptorType] = bvk_add_sat(layout->counts[b->descriptorType], b->descriptorCount);
    }

    AcquireSRWLockExclusive(&bvk_desc_lock);
    if (!bvk_map_put(&bvk_layouts, (uint32_t)(uintptr_t)*pSetLayout, layout))
        free(layout);
    ReleaseSRWLockExclusive(&bvk_desc_lock);
    return r;
}

VKAPI_ATTR void VKAPI_CALL vkDestroyDescriptorSetLayout(VkDevice device, VkDescriptorSetLayout descriptorSetLayout, const VkAllocationCallbacks *pAllocator)
{
    bvk_gen_vkDestroyDescriptorSetLayout(device, descriptorSetLayout, pAllocator);
    AcquireSRWLockExclusive(&bvk_desc_lock);
    free(bvk_map_del(&bvk_layouts, (uint32_t)(uintptr_t)descriptorSetLayout));
    ReleaseSRWLockExclusive(&bvk_desc_lock);
}

VKAPI_ATTR VkResult VKAPI_CALL vkCreateDescriptorPool(VkDevice device, const VkDescriptorPoolCreateInfo *pCreateInfo, const VkAllocationCallbacks *pAllocator, VkDescriptorPool *pDescriptorPool)
{
    bvk_pool_rec* pool = pCreateInfo && pDescriptorPool ? (bvk_pool_rec*)calloc(1, sizeof(bvk_pool_rec)) : NULL;
    if (!pool)
        return bvk_gen_vkCreateDescriptorPool(device, pCreateInfo, pAllocator, pDescriptorPool);
    pool->device = device;
    pool->maxSets = pCreateInfo->maxSets;
    pool->modelable = pCreateInfo->flags == 0 && !pCreateInfo->pNext;
    for (uint32_t i = 0; pool->modelable && i < pCreateInfo->poolSizeCount && pCreateInfo->pPoolSizes; i++)
    {
        const VkDescriptorPoolSize* s = &pCreateInfo->pPoolSizes[i];
        if ((uint32_t)s->type >= BVK_PLAIN_TYPES)
            pool->modelable = 0;
        else
            pool->total[s->type] = bvk_add_sat(pool->total[s->type], s->descriptorCount);
    }
    pool->modeled = pool->modelable;

    uint32_t asked[BVK_PLAIN_TYPES];
    memcpy(asked, pool->total, sizeof(asked));
    AcquireSRWLockExclusive(&bvk_desc_lock);
    int slot = bvk_map_reserve(&bvk_pools);
    if (slot && pool->modelable && !bvk_raise_disabled())
        pool->extra = bvk_desc_raise(device, pool);
    ReleaseSRWLockExclusive(&bvk_desc_lock);

    VkResult r = VK_ERROR_OUT_OF_HOST_MEMORY;
    if (pool->extra)
    {
        VkDescriptorPoolSize sizes[BVK_PLAIN_TYPES];
        uint32_t n = 0;
        for (uint32_t t = 0; t < BVK_PLAIN_TYPES; t++)
            if (pool->total[t])
            {
                sizes[n].type = (VkDescriptorType)t;
                sizes[n++].descriptorCount = pool->total[t];
            }
        VkDescriptorPoolCreateInfo raised = *pCreateInfo;
        raised.poolSizeCount = n;
        raised.pPoolSizes = sizes;
        r = bvk_gen_vkCreateDescriptorPool(device, &raised, pAllocator, pDescriptorPool);
        if (r < 0)
        {
            AcquireSRWLockExclusive(&bvk_desc_lock);
            bvk_raise_left += pool->extra;
            ReleaseSRWLockExclusive(&bvk_desc_lock);
            pool->extra = 0;
            memcpy(pool->total, asked, sizeof(asked));
        }
    }
    if (!pool->extra)
        r = bvk_gen_vkCreateDescriptorPool(device, pCreateInfo, pAllocator, pDescriptorPool);

    AcquireSRWLockExclusive(&bvk_desc_lock);
    if (slot && r >= 0 && bvk_map_put_reserved(&bvk_pools, (uint32_t)(uintptr_t)*pDescriptorPool, pool))
        pool = NULL;
    else
    {
        if (slot)
            bvk_map_unreserve(&bvk_pools);
        bvk_raise_left += pool->extra;
    }
    ReleaseSRWLockExclusive(&bvk_desc_lock);
    free(pool);
    return r;
}

VKAPI_ATTR void VKAPI_CALL vkDestroyDescriptorPool(VkDevice device, VkDescriptorPool descriptorPool, const VkAllocationCallbacks *pAllocator)
{
    bvk_gen_vkDestroyDescriptorPool(device, descriptorPool, pAllocator);
    AcquireSRWLockExclusive(&bvk_desc_lock);
    bvk_pool_rec* pool = (bvk_pool_rec*)bvk_map_del(&bvk_pools, (uint32_t)(uintptr_t)descriptorPool);
    if (pool)
        bvk_raise_left += pool->extra;
    ReleaseSRWLockExclusive(&bvk_desc_lock);
    free(pool);
}

VKAPI_ATTR VkResult VKAPI_CALL vkResetDescriptorPool(VkDevice device, VkDescriptorPool descriptorPool, VkDescriptorPoolResetFlags flags)
{
    VkResult r = bvk_gen_vkResetDescriptorPool(device, descriptorPool, flags);
    if (r < 0)
        return r;

    AcquireSRWLockShared(&bvk_desc_lock);
    bvk_pool_rec* pool = (bvk_pool_rec*)bvk_map_get(&bvk_pools, (uint32_t)(uintptr_t)descriptorPool);
    if (pool)
    {
        pool->sets = 0;
        memset(pool->used, 0, sizeof(pool->used));
        pool->modeled = pool->modelable;
    }
    ReleaseSRWLockShared(&bvk_desc_lock);
    return r;
}

VKAPI_ATTR VkResult VKAPI_CALL vkAllocateDescriptorSets(VkDevice device, const VkDescriptorSetAllocateInfo *pAllocateInfo, VkDescriptorSet *pDescriptorSets)
{
    int posted = pAllocateInfo && !bvk_post_disabled() && bvk_desc_account(pAllocateInfo, 0);
    VkResult r = bvk_gen_vkAllocateDescriptorSets(device, pAllocateInfo, pDescriptorSets, posted);
    if (r >= 0 && pAllocateInfo)
        bvk_desc_account(pAllocateInfo, 1);
    return r;
}

VKAPI_ATTR void VKAPI_CALL vkDestroyDevice(VkDevice device, const VkAllocationCallbacks *pAllocator)
{
    bvk_gen_vkDestroyDevice(device, pAllocator);
    bvk_desc_drop_device(device);
}

typedef struct
{
    VkDescriptorUpdateTemplateEntry* entries;
    uint32_t entryCount;
    VkDescriptorUpdateTemplateType templateType;
    VkPipelineBindPoint pipelineBindPoint;
    VkPipelineLayout pipelineLayout;
    uint32_t set;
} BvkTemplate;

VKAPI_ATTR VkResult VKAPI_CALL vkCreateDescriptorUpdateTemplate(
    VkDevice device, const VkDescriptorUpdateTemplateCreateInfo* pCreateInfo,
    const VkAllocationCallbacks* pAllocator, VkDescriptorUpdateTemplate* pDescriptorUpdateTemplate)
{
    (void)device; (void)pAllocator;
    if (!pCreateInfo || !pDescriptorUpdateTemplate)
        return VK_ERROR_INITIALIZATION_FAILED;
    BvkTemplate* t = (BvkTemplate*)malloc(sizeof(BvkTemplate));
    if (!t)
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    size_t bytes = pCreateInfo->descriptorUpdateEntryCount * sizeof(VkDescriptorUpdateTemplateEntry);
    t->entries = (VkDescriptorUpdateTemplateEntry*)malloc(bytes ? bytes : 1);
    if (!t->entries)
    {
        free(t);
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }
    memcpy(t->entries, pCreateInfo->pDescriptorUpdateEntries, bytes);
    t->entryCount = pCreateInfo->descriptorUpdateEntryCount;
    t->templateType = pCreateInfo->templateType;
    t->pipelineBindPoint = pCreateInfo->pipelineBindPoint;
    t->pipelineLayout = pCreateInfo->pipelineLayout;
    t->set = pCreateInfo->set;
    *pDescriptorUpdateTemplate = (VkDescriptorUpdateTemplate)(uintptr_t)t;
    return VK_SUCCESS;
}

VKAPI_ATTR void VKAPI_CALL vkDestroyDescriptorUpdateTemplate(
    VkDevice device, VkDescriptorUpdateTemplate descriptorUpdateTemplate, const VkAllocationCallbacks* pAllocator)
{
    (void)device; (void)pAllocator;
    BvkTemplate* t = (BvkTemplate*)(uintptr_t)descriptorUpdateTemplate;
    if (!t)
        return;
    free(t->entries);
    free(t);
}

static VkWriteDescriptorSet* bvk_expand_template(
    const BvkTemplate* t, const void* pData, VkDescriptorSet descriptorSet, uint32_t* pWriteCount)
{
    *pWriteCount = 0;
    size_t scratchBytes = 0;
    for (uint32_t i = 0; i < t->entryCount; i++)
        scratchBytes += (size_t)t->entries[i].descriptorCount * sizeof(VkDescriptorImageInfo);
    VkWriteDescriptorSet* writes = (VkWriteDescriptorSet*)malloc(
        t->entryCount * sizeof(VkWriteDescriptorSet) + scratchBytes);
    if (!writes)
        return NULL;
    unsigned char* scratch = (unsigned char*)(writes + t->entryCount);
    uint32_t writeCount = 0;
    for (uint32_t i = 0; i < t->entryCount; i++)
    {
        const VkDescriptorUpdateTemplateEntry* e = &t->entries[i];
        const unsigned char* src = (const unsigned char*)pData + e->offset;
        VkWriteDescriptorSet* w = &writes[writeCount];
        memset(w, 0, sizeof(*w));
        w->sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        w->dstSet = descriptorSet;
        w->dstBinding = e->dstBinding;
        w->dstArrayElement = e->dstArrayElement;
        w->descriptorCount = e->descriptorCount;
        w->descriptorType = e->descriptorType;
        size_t elem;
        int cls;
        switch (e->descriptorType)
        {
        case VK_DESCRIPTOR_TYPE_SAMPLER:
        case VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER:
        case VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE:
        case VK_DESCRIPTOR_TYPE_STORAGE_IMAGE:
        case VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT:
            elem = sizeof(VkDescriptorImageInfo);
            cls = 0;
            break;
        case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER:
        case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER:
        case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC:
        case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC:
            elem = sizeof(VkDescriptorBufferInfo);
            cls = 1;
            break;
        case VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER:
        case VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER:
            elem = sizeof(VkBufferView);
            cls = 2;
            break;
        default:
            continue;
        }
        const void* arr;
        if (e->stride == elem)
            arr = src;
        else
        {
            for (uint32_t k = 0; k < e->descriptorCount; k++)
                memcpy(scratch + k * elem, src + (size_t)k * e->stride, elem);
            arr = scratch;
            scratch += (size_t)e->descriptorCount * elem;
        }
        if (cls == 0)
            w->pImageInfo = (const VkDescriptorImageInfo*)arr;
        else if (cls == 1)
            w->pBufferInfo = (const VkDescriptorBufferInfo*)arr;
        else
            w->pTexelBufferView = (const VkBufferView*)arr;
        writeCount++;
    }
    *pWriteCount = writeCount;
    return writes;
}

VKAPI_ATTR void VKAPI_CALL vkUpdateDescriptorSetWithTemplate(
    VkDevice device, VkDescriptorSet descriptorSet, VkDescriptorUpdateTemplate descriptorUpdateTemplate, const void* pData)
{
    BvkTemplate* t = (BvkTemplate*)(uintptr_t)descriptorUpdateTemplate;
    if (!t || t->templateType != VK_DESCRIPTOR_UPDATE_TEMPLATE_TYPE_DESCRIPTOR_SET || !pData)
        return;
    uint32_t writeCount = 0;
    VkWriteDescriptorSet* writes = bvk_expand_template(t, pData, descriptorSet, &writeCount);
    if (!writes)
        return;
    if (writeCount)
        vkUpdateDescriptorSets(device, writeCount, writes, 0, NULL);
    free(writes);
}

VKAPI_ATTR void VKAPI_CALL vkCmdPushDescriptorSetWithTemplate(
    VkCommandBuffer commandBuffer, VkDescriptorUpdateTemplate descriptorUpdateTemplate,
    VkPipelineLayout layout, uint32_t set, const void* pData)
{
    BvkTemplate* t = (BvkTemplate*)(uintptr_t)descriptorUpdateTemplate;
    if (!t || t->templateType != VK_DESCRIPTOR_UPDATE_TEMPLATE_TYPE_PUSH_DESCRIPTORS || !pData)
        return;
    uint32_t writeCount = 0;
    VkWriteDescriptorSet* writes = bvk_expand_template(t, pData, VK_NULL_HANDLE, &writeCount);
    if (!writes)
        return;
    if (writeCount)
        vkCmdPushDescriptorSet(commandBuffer, t->pipelineBindPoint,
                               layout ? layout : t->pipelineLayout, set, writeCount, writes);
    free(writes);
}

VKAPI_ATTR void VKAPI_CALL vkCmdPushDescriptorSetWithTemplate2(
    VkCommandBuffer commandBuffer, const VkPushDescriptorSetWithTemplateInfo* pInfo)
{
    if (!pInfo)
        return;
    vkCmdPushDescriptorSetWithTemplate(commandBuffer, pInfo->descriptorUpdateTemplate,
                                       pInfo->layout, pInfo->set, pInfo->pData);
}

typedef struct
{
    uint64_t objectHandle;
    uint64_t value;
    uint32_t objectType;
} BvkPrivateEntry;

typedef struct
{
    SRWLOCK lock;
    BvkPrivateEntry* entries;
    uint32_t count;
    uint32_t cap;
} BvkPrivateSlot;

VKAPI_ATTR VkResult VKAPI_CALL vkCreatePrivateDataSlot(
    VkDevice device, const VkPrivateDataSlotCreateInfo* pCreateInfo,
    const VkAllocationCallbacks* pAllocator, VkPrivateDataSlot* pPrivateDataSlot)
{
    (void)device; (void)pCreateInfo; (void)pAllocator;
    if (!pPrivateDataSlot)
        return VK_ERROR_INITIALIZATION_FAILED;
    BvkPrivateSlot* s = (BvkPrivateSlot*)calloc(1, sizeof(BvkPrivateSlot));
    if (!s)
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    InitializeSRWLock(&s->lock);
    *pPrivateDataSlot = (VkPrivateDataSlot)(uintptr_t)s;
    return VK_SUCCESS;
}

VKAPI_ATTR void VKAPI_CALL vkDestroyPrivateDataSlot(
    VkDevice device, VkPrivateDataSlot privateDataSlot, const VkAllocationCallbacks* pAllocator)
{
    (void)device; (void)pAllocator;
    BvkPrivateSlot* s = (BvkPrivateSlot*)(uintptr_t)privateDataSlot;
    if (!s)
        return;
    free(s->entries);
    free(s);
}

VKAPI_ATTR VkResult VKAPI_CALL vkSetPrivateData(
    VkDevice device, VkObjectType objectType, uint64_t objectHandle,
    VkPrivateDataSlot privateDataSlot, uint64_t data)
{
    (void)device;
    BvkPrivateSlot* s = (BvkPrivateSlot*)(uintptr_t)privateDataSlot;
    if (!s)
        return VK_ERROR_INITIALIZATION_FAILED;
    AcquireSRWLockExclusive(&s->lock);
    for (uint32_t i = 0; i < s->count; i++)
        if (s->entries[i].objectHandle == objectHandle && s->entries[i].objectType == (uint32_t)objectType)
        {
            s->entries[i].value = data;
            ReleaseSRWLockExclusive(&s->lock);
            return VK_SUCCESS;
        }
    if (s->count == s->cap)
    {
        uint32_t ncap = s->cap ? s->cap * 2 : 16;
        BvkPrivateEntry* ne = (BvkPrivateEntry*)realloc(s->entries, ncap * sizeof(BvkPrivateEntry));
        if (!ne)
        {
            ReleaseSRWLockExclusive(&s->lock);
            return VK_ERROR_OUT_OF_HOST_MEMORY;
        }
        s->entries = ne;
        s->cap = ncap;
    }
    s->entries[s->count].objectHandle = objectHandle;
    s->entries[s->count].objectType = (uint32_t)objectType;
    s->entries[s->count].value = data;
    s->count++;
    ReleaseSRWLockExclusive(&s->lock);
    return VK_SUCCESS;
}

VKAPI_ATTR void VKAPI_CALL vkGetPrivateData(
    VkDevice device, VkObjectType objectType, uint64_t objectHandle,
    VkPrivateDataSlot privateDataSlot, uint64_t* pData)
{
    (void)device;
    BvkPrivateSlot* s = (BvkPrivateSlot*)(uintptr_t)privateDataSlot;
    if (!pData)
        return;
    *pData = 0;
    if (!s)
        return;
    AcquireSRWLockShared(&s->lock);
    for (uint32_t i = 0; i < s->count; i++)
        if (s->entries[i].objectHandle == objectHandle && s->entries[i].objectType == (uint32_t)objectType)
        {
            *pData = s->entries[i].value;
            break;
        }
    ReleaseSRWLockShared(&s->lock);
}

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(VkInstance instance, const char* pName)
{
    (void)instance;
    if (!pName)
        return NULL;

#define M(n)                                        \
    if (strcmp(pName, #n) == 0)                      \
    return (PFN_vkVoidFunction)n

    M(vkGetInstanceProcAddr);
    M(vkGetDeviceProcAddr);
    M(vkEnumerateInstanceLayerProperties);
    M(vkEnumerateDeviceLayerProperties);
    M(vkCreateDescriptorUpdateTemplate);
    M(vkDestroyDescriptorUpdateTemplate);
    M(vkUpdateDescriptorSetWithTemplate);
    M(vkCmdPushDescriptorSetWithTemplate);
    M(vkCmdPushDescriptorSetWithTemplate2);
    M(vkCreatePrivateDataSlot);
    M(vkDestroyPrivateDataSlot);
    M(vkSetPrivateData);
    M(vkGetPrivateData);
#include "obj/generated/brovvulk_gen_procs.inc"
#undef M

    return NULL;
}

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(VkDevice device, const char* pName)
{
    (void)device;
    return vkGetInstanceProcAddr(VK_NULL_HANDLE, pName);
}
