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
#else
#define BVK_TLS __thread
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
    uint32_t *pPropertyCount, VkLayerProperties *pProperties)
{
    (void)pProperties;
    if (pPropertyCount)
        *pPropertyCount = 0;
    return VK_SUCCESS;
}

#define BVK_HDR 8u

static BVK_TLS unsigned char *bvk_rq;
static BVK_TLS unsigned int bvk_rqcap;
static BVK_TLS unsigned int bvk_rqlen;

static void bvk_rq_grow(unsigned int need)
{
    if (need <= bvk_rqcap)
        return;
    unsigned int nc = bvk_rqcap ? bvk_rqcap : 8192u;
    while (nc < need)
        nc *= 2u;
    unsigned char *nb = (unsigned char *)realloc(bvk_rq, nc);
    if (nb) { bvk_rq = nb; bvk_rqcap = nc; }
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

static void bvk_w_bytes(const void *s, unsigned int len)
{
    bvk_rq_grow(bvk_rqlen + len);
    if (len)
        memcpy(bvk_rq + bvk_rqlen, s, len);
    bvk_rqlen += len;
}

static int bvk_rq_send(uint32_t cmd, void *out, uint32_t outCap, uint32_t *outLen)
{
    HANDLE h = brov_dev();
    if (h == INVALID_HANDLE_VALUE)
        return VK_ERROR_INITIALIZATION_FAILED;

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
    void *map;
} bvk_mem_entry;

static SRWLOCK bvk_mem_lock = SRWLOCK_INIT;
static bvk_mem_entry *bvk_mem_tab;
static unsigned int bvk_mem_count;
static unsigned int bvk_mem_cap;

static bvk_mem_entry *bvk_mem_find(uint32_t id)
{
    for (unsigned int i = 0; i < bvk_mem_count; i++)
        if (bvk_mem_tab[i].id == id)
            return &bvk_mem_tab[i];
    return NULL;
}

static void bvk_mem_add(uint32_t id, uint64_t size)
{
    AcquireSRWLockExclusive(&bvk_mem_lock);
    if (bvk_mem_count == bvk_mem_cap)
    {
        unsigned int nc = bvk_mem_cap ? bvk_mem_cap * 2u : 64u;
        bvk_mem_entry *nt = (bvk_mem_entry *)realloc(bvk_mem_tab, nc * sizeof(bvk_mem_entry));
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
    bvk_mem_count++;
    ReleaseSRWLockExclusive(&bvk_mem_lock);
}

static int bvk_mem_size(uint32_t id, uint64_t *size)
{
    AcquireSRWLockShared(&bvk_mem_lock);
    bvk_mem_entry *e = bvk_mem_find(id);
    if (e)
        *size = e->size;
    ReleaseSRWLockShared(&bvk_mem_lock);
    return e != NULL;
}

static int bvk_mem_mapped(uint32_t id)
{
    AcquireSRWLockShared(&bvk_mem_lock);
    bvk_mem_entry *e = bvk_mem_find(id);
    int mapped = e != NULL && e->map != NULL;
    ReleaseSRWLockShared(&bvk_mem_lock);
    return mapped;
}

static void bvk_mem_setmap(uint32_t id, void *map)
{
    AcquireSRWLockExclusive(&bvk_mem_lock);
    bvk_mem_entry *e = bvk_mem_find(id);
    if (e)
        e->map = map;
    ReleaseSRWLockExclusive(&bvk_mem_lock);
}

static void bvk_mem_clearmap(uint32_t id)
{
    AcquireSRWLockExclusive(&bvk_mem_lock);
    bvk_mem_entry *e = bvk_mem_find(id);
    void *map = NULL;
    if (e)
    {
        map = e->map;
        e->map = NULL;
    }
    ReleaseSRWLockExclusive(&bvk_mem_lock);
    if (map)
        VirtualFree(map, 0, MEM_RELEASE);
}

static void bvk_mem_remove(uint32_t id)
{
    AcquireSRWLockExclusive(&bvk_mem_lock);
    bvk_mem_entry *e = bvk_mem_find(id);
    void *map = NULL;
    if (e)
    {
        map = e->map;
        *e = bvk_mem_tab[--bvk_mem_count];
    }
    ReleaseSRWLockExclusive(&bvk_mem_lock);
    if (map)
        VirtualFree(map, 0, MEM_RELEASE);
}

#include "obj/generated/brovvulk_structs.h"

static void bvk_ser_struct(int sid, const unsigned char *s)
{
    const BvkM *mm = bvk_structs[sid];
    int mc = bvk_struct_counts[sid];
    for (int i = 0; i < mc; i++)
    {
        const BvkM *d = &mm[i];
        const unsigned char *fp = s + d->offset;
        switch (d->kind)
        {
        case 0:
            bvk_w_bytes(fp, (unsigned int)d->size);
            break;
        case 1:
            bvk_w_u32((uint32_t)(uintptr_t)(*(void *const *)fp));
            break;
        case 2:
            bvk_ser_struct(d->sub, fp);
            break;
        case 3:
        {
            const void *p = *(const void *const *)fp;
            if (p) { bvk_w_u32(1); bvk_ser_struct(d->sub, (const unsigned char *)p); }
            else bvk_w_u32(0);
            break;
        }
        case 4:
        {
            const void *p = *(const void *const *)fp;
            uint32_t n = *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); for (uint32_t k = 0; k < n; k++) bvk_ser_struct(d->sub, (const unsigned char *)p + (size_t)k * bvk_struct_sizes[d->sub]); }
            else bvk_w_u32(0);
            break;
        }
        case 5:
        {
            const void *const *p = *(const void *const *const *)fp;
            uint32_t n = *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); for (uint32_t k = 0; k < n; k++) bvk_w_u32((uint32_t)(uintptr_t)p[k]); }
            else bvk_w_u32(0);
            break;
        }
        case 6:
        {
            const void *p = *(const void *const *)fp;
            uint32_t n = *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); bvk_w_bytes(p, n * (unsigned int)d->size); }
            else bvk_w_u32(0);
            break;
        }
        case 7:
        {
            const char *p = *(const char *const *)fp;
            if (p) { uint32_t l = (uint32_t)strlen(p) + 1; bvk_w_u32(l); bvk_w_bytes(p, l); }
            else bvk_w_u32(0);
            break;
        }
        case 8:
        {
            const char *const *p = *(const char *const *const *)fp;
            uint32_t n = *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); for (uint32_t k = 0; k < n; k++) { uint32_t l = (uint32_t)strlen(p[k]) + 1; bvk_w_u32(l); bvk_w_bytes(p[k], l); } }
            else bvk_w_u32(0);
            break;
        }
        case 9:
        {
            const void *pn = *(const void *const *)fp;
            while (pn)
            {
                int psid = bvk_pnext_sid(*(const uint32_t *)pn);
                if (psid >= 0)
                {
                    bvk_w_u32(1);
                    bvk_w_u32((uint32_t)psid);
                    bvk_ser_struct(psid, (const unsigned char *)pn);
                    break;
                }
                pn = *(const void *const *)((const char *)pn + 8);
            }
            if (!pn)
                bvk_w_u32(0);
            break;
        }
        case 11:
        {
            const void *p = *(const void *const *)fp;
            uint32_t n = d->size == 8
                ? (uint32_t)(*(const uint64_t *)(s + d->lenOffset))
                : *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); bvk_w_bytes(p, n); }
            else bvk_w_u32(0);
            break;
        }
        case 12:
        {
            uint32_t dt = *(const uint32_t *)(s + d->selOffset);
            if (dt < 32 && (d->selMask & (1u << dt)))
            {
                const void *p = *(const void *const *)fp;
                uint32_t n = *(const uint32_t *)(s + d->lenOffset);
                if (p)
                {
                    bvk_w_u32(n);
                    if (d->sub >= 0)
                        for (uint32_t k = 0; k < n; k++)
                            bvk_ser_struct(d->sub, (const unsigned char *)p + (size_t)k * bvk_struct_sizes[d->sub]);
                    else
                        for (uint32_t k = 0; k < n; k++)
                            bvk_w_u32((uint32_t)(uintptr_t)((const void *const *)p)[k]);
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

#define BVK_BATCH_ID 0xFFFFFFFEu
#define BVK_BATCH_LIMIT 900000u

typedef struct
{
    VkCommandBuffer cb;
    unsigned char *buf;
    unsigned int cap, len, count;
} bvk_rec_slot;

static SRWLOCK bvk_rec_lock = SRWLOCK_INIT;
static bvk_rec_slot *bvk_rec_tab;
static unsigned int bvk_rec_ntab;

static bvk_rec_slot *bvk_rec_slot_for(VkCommandBuffer cb)
{
    bvk_rec_slot *fre = NULL;
    for (unsigned int i = 0; i < bvk_rec_ntab; i++)
    {
        if (bvk_rec_tab[i].cb == cb)
            return &bvk_rec_tab[i];
        if (!fre && bvk_rec_tab[i].cb == VK_NULL_HANDLE)
            fre = &bvk_rec_tab[i];
    }
    if (fre) { fre->cb = cb; return fre; }
    unsigned int ni = bvk_rec_ntab + 8u;
    bvk_rec_slot *nt = (bvk_rec_slot *)realloc(bvk_rec_tab, ni * sizeof(bvk_rec_slot));
    if (!nt)
        return NULL;
    memset(nt + bvk_rec_ntab, 0, 8u * sizeof(bvk_rec_slot));
    bvk_rec_tab = nt;
    bvk_rec_slot *s = &bvk_rec_tab[bvk_rec_ntab];
    s->cb = cb;
    bvk_rec_ntab = ni;
    return s;
}

static void bvk_rec_slot_grow(bvk_rec_slot *s, unsigned int need)
{
    if (need <= s->cap)
        return;
    unsigned int nc = s->cap ? s->cap : 65536u;
    while (nc < need)
        nc *= 2u;
    unsigned char *nb = (unsigned char *)realloc(s->buf, nc);
    if (nb) { s->buf = nb; s->cap = nc; }
}

static void bvk_rec_begin(VkCommandBuffer cb)
{
    AcquireSRWLockExclusive(&bvk_rec_lock);
    bvk_rec_slot *s = bvk_rec_slot_for(cb);
    if (s)
    {
        bvk_rec_slot_grow(s, BVK_HDR + 4);
        s->len = BVK_HDR + 4;
        s->count = 0;
    }
    ReleaseSRWLockExclusive(&bvk_rec_lock);
}

static int bvk_rec_dispatch_slot(bvk_rec_slot *s)
{
    uint32_t plen = s->len - BVK_HDR;
    uint32_t cmd = BVK_BATCH_ID;
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

static void bvk_rec_append(VkCommandBuffer cb, uint32_t id)
{
    AcquireSRWLockExclusive(&bvk_rec_lock);
    bvk_rec_slot *s = bvk_rec_slot_for(cb);
    if (s)
    {
        unsigned int args = bvk_rqlen - BVK_HDR;
        if (s->count != 0 && (uint64_t)s->len + 4 + args > BVK_BATCH_LIMIT)
            bvk_rec_dispatch_slot(s);
        bvk_rec_slot_grow(s, s->len + 4 + args);
        memcpy(s->buf + s->len, &id, 4);
        s->len += 4;
        memcpy(s->buf + s->len, bvk_rq + BVK_HDR, args);
        s->len += args;
        s->count++;
    }
    ReleaseSRWLockExclusive(&bvk_rec_lock);
}

static int bvk_rec_flush(VkCommandBuffer cb)
{
    AcquireSRWLockExclusive(&bvk_rec_lock);
    bvk_rec_slot *s = bvk_rec_slot_for(cb);
    int r = VK_SUCCESS;
    if (s)
    {
        r = bvk_rec_dispatch_slot(s);
        s->cb = VK_NULL_HANDLE;
    }
    ReleaseSRWLockExclusive(&bvk_rec_lock);
    return r;
}

#include "obj/generated/brovvulk_gen.c"

typedef struct
{
    VkDescriptorUpdateTemplateEntry *entries;
    uint32_t entryCount;
    VkDescriptorUpdateTemplateType templateType;
} BvkTemplate;

VKAPI_ATTR VkResult VKAPI_CALL vkCreateDescriptorUpdateTemplate(
    VkDevice device, const VkDescriptorUpdateTemplateCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkDescriptorUpdateTemplate *pDescriptorUpdateTemplate)
{
    (void)device; (void)pAllocator;
    if (!pCreateInfo || !pDescriptorUpdateTemplate)
        return VK_ERROR_INITIALIZATION_FAILED;
    BvkTemplate *t = (BvkTemplate *)malloc(sizeof(BvkTemplate));
    if (!t)
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    size_t bytes = pCreateInfo->descriptorUpdateEntryCount * sizeof(VkDescriptorUpdateTemplateEntry);
    t->entries = (VkDescriptorUpdateTemplateEntry *)malloc(bytes ? bytes : 1);
    if (!t->entries)
    {
        free(t);
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }
    memcpy(t->entries, pCreateInfo->pDescriptorUpdateEntries, bytes);
    t->entryCount = pCreateInfo->descriptorUpdateEntryCount;
    t->templateType = pCreateInfo->templateType;
    *pDescriptorUpdateTemplate = (VkDescriptorUpdateTemplate)(uintptr_t)t;
    return VK_SUCCESS;
}

VKAPI_ATTR void VKAPI_CALL vkDestroyDescriptorUpdateTemplate(
    VkDevice device, VkDescriptorUpdateTemplate descriptorUpdateTemplate, const VkAllocationCallbacks *pAllocator)
{
    (void)device; (void)pAllocator;
    BvkTemplate *t = (BvkTemplate *)(uintptr_t)descriptorUpdateTemplate;
    if (!t)
        return;
    free(t->entries);
    free(t);
}

VKAPI_ATTR void VKAPI_CALL vkUpdateDescriptorSetWithTemplate(
    VkDevice device, VkDescriptorSet descriptorSet, VkDescriptorUpdateTemplate descriptorUpdateTemplate, const void *pData)
{
    BvkTemplate *t = (BvkTemplate *)(uintptr_t)descriptorUpdateTemplate;
    if (!t || t->templateType != VK_DESCRIPTOR_UPDATE_TEMPLATE_TYPE_DESCRIPTOR_SET || !pData)
        return;
    size_t scratchBytes = 0;
    for (uint32_t i = 0; i < t->entryCount; i++)
        scratchBytes += (size_t)t->entries[i].descriptorCount * sizeof(VkDescriptorImageInfo);
    VkWriteDescriptorSet *writes = (VkWriteDescriptorSet *)malloc(
        t->entryCount * sizeof(VkWriteDescriptorSet) + scratchBytes);
    if (!writes)
        return;
    unsigned char *scratch = (unsigned char *)(writes + t->entryCount);
    uint32_t writeCount = 0;
    for (uint32_t i = 0; i < t->entryCount; i++)
    {
        const VkDescriptorUpdateTemplateEntry *e = &t->entries[i];
        const unsigned char *src = (const unsigned char *)pData + e->offset;
        VkWriteDescriptorSet *w = &writes[writeCount];
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
        const void *arr;
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
            w->pImageInfo = (const VkDescriptorImageInfo *)arr;
        else if (cls == 1)
            w->pBufferInfo = (const VkDescriptorBufferInfo *)arr;
        else
            w->pTexelBufferView = (const VkBufferView *)arr;
        writeCount++;
    }
    if (writeCount)
        vkUpdateDescriptorSets(device, writeCount, writes, 0, NULL);
    free(writes);
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
    BvkPrivateEntry *entries;
    uint32_t count;
    uint32_t cap;
} BvkPrivateSlot;

VKAPI_ATTR VkResult VKAPI_CALL vkCreatePrivateDataSlot(
    VkDevice device, const VkPrivateDataSlotCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkPrivateDataSlot *pPrivateDataSlot)
{
    (void)device; (void)pCreateInfo; (void)pAllocator;
    if (!pPrivateDataSlot)
        return VK_ERROR_INITIALIZATION_FAILED;
    BvkPrivateSlot *s = (BvkPrivateSlot *)calloc(1, sizeof(BvkPrivateSlot));
    if (!s)
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    InitializeSRWLock(&s->lock);
    *pPrivateDataSlot = (VkPrivateDataSlot)(uintptr_t)s;
    return VK_SUCCESS;
}

VKAPI_ATTR void VKAPI_CALL vkDestroyPrivateDataSlot(
    VkDevice device, VkPrivateDataSlot privateDataSlot, const VkAllocationCallbacks *pAllocator)
{
    (void)device; (void)pAllocator;
    BvkPrivateSlot *s = (BvkPrivateSlot *)(uintptr_t)privateDataSlot;
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
    BvkPrivateSlot *s = (BvkPrivateSlot *)(uintptr_t)privateDataSlot;
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
        BvkPrivateEntry *ne = (BvkPrivateEntry *)realloc(s->entries, ncap * sizeof(BvkPrivateEntry));
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
    VkPrivateDataSlot privateDataSlot, uint64_t *pData)
{
    (void)device;
    BvkPrivateSlot *s = (BvkPrivateSlot *)(uintptr_t)privateDataSlot;
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

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(VkInstance instance, const char *pName)
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
    M(vkCreateDescriptorUpdateTemplate);
    M(vkDestroyDescriptorUpdateTemplate);
    M(vkUpdateDescriptorSetWithTemplate);
    M(vkCreatePrivateDataSlot);
    M(vkDestroyPrivateDataSlot);
    M(vkSetPrivateData);
    M(vkGetPrivateData);
#include "obj/generated/brovvulk_gen_procs.inc"
#undef M

    return NULL;
}

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(VkDevice device, const char *pName)
{
    (void)device;
    return vkGetInstanceProcAddr(VK_NULL_HANDLE, pName);
}
