#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "obj/generated/brovsteam_gen.h"

#define IOCTL_BROVSTEAM_CALL 0x80002400u

#define BS_HDR 8u
#define BS_RING_SLOT 8192u
#define BS_RING_SLOTS 8u
#define BS_MAX_BUF (1u << 26)

#if defined(_MSC_VER)
#define BS_TLS __declspec(thread)
#else
#define BS_TLS __thread
#endif

#define BS_CREATE_INTERFACE 1u
#define BS_BGETCALLBACK 2u
#define BS_GETAPICALLRESULT 3u
#define BS_NOTIFYMISSING 6u

typedef struct
{
    const void** vt;
    uint32_t id;
} BsObj;

typedef struct
{
    const char** strings;
    int32_t count;
} BsStringArray;

static HANDLE g_dev = INVALID_HANDLE_VALUE;
static SRWLOCK g_devLock = SRWLOCK_INIT;

static HANDLE bs_dev(void)
{
    if (g_dev == INVALID_HANDLE_VALUE)
    {
        AcquireSRWLockExclusive(&g_devLock);
        if (g_dev == INVALID_HANDLE_VALUE)
        {
            g_dev = CreateFileW(L"\\\\.\\BrovSteam", GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);
        }
        ReleaseSRWLockExclusive(&g_devLock);
    }
    return g_dev;
}

static BS_TLS unsigned char* bs_rq;
static BS_TLS uint32_t bs_rqcap;
static BS_TLS uint32_t bs_rqlen;
static BS_TLS unsigned char* bs_rs;
static BS_TLS uint32_t bs_rscap;
static BS_TLS uint32_t bs_rspos;
static BS_TLS uint32_t bs_rslen;
static BS_TLS char* bs_ring;
static BS_TLS unsigned int bs_ringNext;

static void bs_grow(unsigned char** buf, uint32_t* cap, uint32_t need)
{
    if (need <= *cap)
        return;
    if (need > BS_MAX_BUF)
        return;
    uint32_t nc = *cap ? *cap : 8192u;
    while (nc < need)
        nc *= 2u;
    unsigned char* nb = (unsigned char*)realloc(*buf, nc);
    if (nb)
    {
        *buf = nb;
        *cap = nc;
    }
}

static void bs_rq_reset(void)
{
    bs_grow(&bs_rq, &bs_rqcap, BS_HDR);
    bs_rqlen = BS_HDR;
}

static void bs_w_bytes(const void* src, uint32_t len)
{
    // A signed count that arrived negative reaches here huge, so bound it before the sum.
    if (len > BS_MAX_BUF || bs_rqlen > BS_MAX_BUF - len)
        return;
    bs_grow(&bs_rq, &bs_rqcap, bs_rqlen + len);
    if (bs_rqlen + len > bs_rqcap)
        return;
    if (len)
        memcpy(bs_rq + bs_rqlen, src, len);
    bs_rqlen += len;
}

static void bs_w_u32(uint32_t v) { bs_w_bytes(&v, 4); }
static void bs_w_u64(uint64_t v) { bs_w_bytes(&v, 8); }
static void bs_w_f32(float v) { bs_w_bytes(&v, 4); }
static void bs_w_f64(double v) { bs_w_bytes(&v, 8); }

static void bs_w_str(const char* s)
{
    if (!s)
    {
        bs_w_u32(0);
        return;
    }
    uint32_t n = (uint32_t)strlen(s);
    bs_w_u32(n + 1u);
    bs_w_bytes(s, n);
}

static void bs_w_blob(const void* p, uint32_t n)
{
    if (!p)
    {
        bs_w_u32(0);
        return;
    }
    bs_w_u32(1);
    bs_w_u32(n);
    bs_w_bytes(p, n);
}

static void bs_w_out(const void* p, uint32_t cap)
{
    if (!p)
    {
        bs_w_u32(0);
        return;
    }
    bs_w_u32(1);
    bs_w_u32(cap);
}

static void bs_w_strarray(const BsStringArray* a)
{
    if (!a)
    {
        bs_w_u32(0);
        return;
    }
    bs_w_u32(1);
    int32_t n = a->count < 0 ? 0 : a->count;
    bs_w_u32((uint32_t)n);
    for (int32_t i = 0; i < n; i++)
        bs_w_str(a->strings ? a->strings[i] : NULL);
}

static int bs_call(uint32_t id, uint32_t need)
{
    HANDLE h = bs_dev();
    if (h == INVALID_HANDLE_VALUE)
        return -1;

    uint32_t plen = bs_rqlen - BS_HDR;
    memcpy(bs_rq + 0, &id, 4);
    memcpy(bs_rq + 4, &plen, 4);

    if (need < 256u)
        need = 256u;
    bs_grow(&bs_rs, &bs_rscap, need);
    if (bs_rscap < need)
        return -1;

    // The buffer keeps the high water mark of every call on this thread, the device is told only
    // what this call can produce, so it does not clear and copy the rest.
    uint32_t outLen = need;

    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_BROVSTEAM_CALL, bs_rq, bs_rqlen, bs_rs, outLen, &ret, NULL) || ret < 4)
        return -1;

    // The device truncates a reply that does not fit, so reads stay inside what arrived.
    bs_rslen = (uint32_t)ret > outLen ? outLen : (uint32_t)ret;
    bs_rspos = 4;

    uint32_t status;
    memcpy(&status, bs_rs, 4);
    return status == 0 ? 0 : -1;
}

static void bs_r_bytes(void* dst, uint32_t n)
{
    if (bs_rspos + n > bs_rslen)
    {
        memset(dst, 0, n);
        bs_rspos = bs_rslen;
        return;
    }
    memcpy(dst, bs_rs + bs_rspos, n);
    bs_rspos += n;
}

static uint32_t bs_r_u32(void) { uint32_t v; bs_r_bytes(&v, 4); return v; }
static uint64_t bs_r_u64(void) { uint64_t v; bs_r_bytes(&v, 8); return v; }
static float bs_r_f32(void) { float v; bs_r_bytes(&v, 4); return v; }
static double bs_r_f64(void) { double v; bs_r_bytes(&v, 8); return v; }

static char* bs_ring_slot(void)
{
    if (!bs_ring)
    {
        bs_ring = (char*)malloc(BS_RING_SLOT * BS_RING_SLOTS);
        if (!bs_ring)
            return NULL;
    }
    char* slot = bs_ring + (bs_ringNext % BS_RING_SLOTS) * BS_RING_SLOT;
    bs_ringNext++;
    return slot;
}

static const char* bs_r_ring(void)
{
    uint32_t v = bs_r_u32();
    if (v == 0)
        return "";

    uint32_t n = v - 1u;
    char* slot = bs_ring_slot();
    if (!slot)
        return "";

    if (n > BS_RING_SLOT - 1u)
        n = BS_RING_SLOT - 1u;
    bs_r_bytes(slot, n);
    slot[n] = 0;
    return slot;
}

static void bs_r_out(void* p, uint32_t size)
{
    if (!p)
        return;
    bs_r_bytes(p, size);
}

static void bs_r_outbuf(void* p, uint32_t cap)
{
    if (!p)
        return;
    uint32_t n = bs_r_u32();
    if (n > cap)
        n = cap;
    bs_r_bytes(p, n);
}

static void bs_r_outstrptr(char** p)
{
    if (!p)
        return;
    *p = (char*)bs_r_ring();
}

static BsObj* bs_objs;
static unsigned int bs_objCount;
static unsigned int bs_objCap;
static SRWLOCK bs_objLock = SRWLOCK_INIT;

static void* bs_obj(uint32_t id, const void** vt)
{
    AcquireSRWLockExclusive(&bs_objLock);
    for (unsigned int i = 0; i < bs_objCount; i++)
    {
        if (bs_objs[i].id == id && bs_objs[i].vt == vt)
        {
            void* found = &bs_objs[i];
            ReleaseSRWLockExclusive(&bs_objLock);
            return found;
        }
    }

    if (bs_objCount == bs_objCap)
    {
        unsigned int nc = bs_objCap ? bs_objCap * 2u : 64u;
        BsObj* nt = (BsObj*)malloc(nc * sizeof(BsObj));
        if (!nt)
        {
            ReleaseSRWLockExclusive(&bs_objLock);
            return NULL;
        }
        if (bs_objs)
            memcpy(nt, bs_objs, bs_objCount * sizeof(BsObj));
        // Old entries stay live, the game holds pointers into them.
        bs_objs = nt;
        bs_objCap = nc;
    }

    bs_objs[bs_objCount].vt = vt;
    bs_objs[bs_objCount].id = id;
    void* made = &bs_objs[bs_objCount];
    bs_objCount++;
    ReleaseSRWLockExclusive(&bs_objLock);
    return made;
}

static void* bs_wrap(uint32_t id, const char* version)
{
    if (!id)
        return NULL;
    const void** vt = bs_vtable_for(version);
    return vt ? bs_obj(id, vt) : NULL;
}

#include "obj/generated/brovsteam_gen.c"

__declspec(dllexport) void* CreateInterface(const char* version, int* returnCode)
{
    bs_rq_reset();
    bs_w_str(version);
    if (bs_call(BS_CREATE_INTERFACE, 256u) != 0)
    {
        if (returnCode)
            *returnCode = 1;
        return NULL;
    }

    void* obj = bs_wrap(bs_r_u32(), version);
    if (returnCode)
        *returnCode = obj ? 0 : 1;
    return obj;
}

typedef struct
{
    int32_t m_hSteamUser;
    int32_t m_iCallback;
    uint8_t* m_pubParam;
    int32_t m_cubParam;
} BsCallbackMsg;

static BS_TLS unsigned char* bs_cb;
static BS_TLS uint32_t bs_cbcap;

__declspec(dllexport) uint8_t Steam_BGetCallback(int32_t pipe, BsCallbackMsg* msg, int32_t* call)
{
    if (!msg)
        return 0;

    bs_rq_reset();
    bs_w_u32((uint32_t)pipe);
    if (bs_call(BS_BGETCALLBACK, (1u << 16) + 64u) != 0)
        return 0;

    uint32_t got = bs_r_u32();
    if (!got)
        return 0;

    msg->m_hSteamUser = (int32_t)bs_r_u32();
    msg->m_iCallback = (int32_t)bs_r_u32();
    uint32_t n = bs_r_u32();
    bs_grow(&bs_cb, &bs_cbcap, n ? n : 1u);
    if (bs_cbcap < n)
        return 0;

    bs_r_bytes(bs_cb, n);
    msg->m_pubParam = bs_cb;
    msg->m_cubParam = (int32_t)n;
    if (call)
        *call = 0;
    return 1;
}

__declspec(dllexport) uint8_t Steam_FreeLastCallback(int32_t pipe)
{
    (void)pipe;
    return 1;
}

__declspec(dllexport) uint8_t Steam_GetAPICallResult(int32_t pipe, uint64_t call, void* buffer,
    int32_t bufferSize, int32_t expected, uint8_t* failed)
{
    bs_rq_reset();
    bs_w_u32((uint32_t)pipe);
    bs_w_u64(call);
    bs_w_u32((uint32_t)(bufferSize < 0 ? 0 : bufferSize));
    bs_w_u32((uint32_t)expected);
    if (bs_call(BS_GETAPICALLRESULT, (uint32_t)(bufferSize < 0 ? 0 : bufferSize) + 64u) != 0)
        return 0;

    uint8_t ok = (uint8_t)bs_r_u32();
    uint8_t didFail = (uint8_t)bs_r_u32();
    uint32_t n = bs_r_u32();
    if (buffer && bufferSize > 0)
    {
        if (n > (uint32_t)bufferSize)
            n = (uint32_t)bufferSize;
        bs_r_bytes(buffer, n);
    }

    if (failed)
        *failed = didFail;
    return ok;
}

__declspec(dllexport) void Steam_ReleaseThreadLocalMemory(int32_t threadLocal)
{
    (void)threadLocal;
}

__declspec(dllexport) uint8_t Steam_IsKnownInterface(const char* version)
{
    return bs_version_index(version) >= 0 ? 1u : 0u;
}

__declspec(dllexport) void Steam_NotifyMissingInterface(int32_t pipe, const char* version)
{
    bs_rq_reset();
    bs_w_u32((uint32_t)pipe);
    bs_w_str(version);
    bs_call(BS_NOTIFYMISSING, 64u);
}

__declspec(dllexport) void Breakpad_SteamMiniDumpInit(uint32_t a, const char* b, const char* c)
{
    (void)a; (void)b; (void)c;
}

__declspec(dllexport) void Breakpad_SteamSetAppID(uint32_t appId) { (void)appId; }

__declspec(dllexport) int32_t Breakpad_SteamSetSteamID(uint64_t steamId) { (void)steamId; return 0; }

__declspec(dllexport) int32_t Breakpad_SteamWriteMiniDumpSetComment(const char* comment) { (void)comment; return 0; }

__declspec(dllexport) void Breakpad_SteamWriteMiniDumpUsingExceptionInfoWithBuildId(int32_t a, int32_t b)
{
    (void)a; (void)b;
}

__declspec(dllexport) void Breakpad_SteamSendMiniDump(void* a, const char* b, uint32_t c)
{
    (void)a; (void)b; (void)c;
}
