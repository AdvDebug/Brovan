/* Included into brovan_direct_window.inc.c on an aarch64 Linux host. */

#include <ucontext.h>

/* The only register-offset load or store with base x28 and offset x3, followed by a b. */
static bool brov_direct_site_at(uintptr_t pc, uintptr_t code_lo, uintptr_t code_hi)
{
    uint32_t insn;
    uint32_t next;

    if ((pc & 3) != 0 || pc < code_lo || code_hi - pc < 8) {
        return false;
    }
    insn = *(const uint32_t *)pc;
    next = *(const uint32_t *)(pc + 4);
    return (insn & 0x3b200c00u) == 0x38200800u && ((insn >> 5) & 31u) == 28u && ((insn >> 16) & 31u) == 3u &&
           (next & 0xfc000000u) == 0x14000000u;
}

static uintptr_t brov_direct_site_probe(uintptr_t pc)
{
    return pc + 8;
}

static void brov_direct_site_patch(uintptr_t pc)
{
    *(volatile uint32_t *)pc = 0x14000002u; /* b #8 */
    __builtin___clear_cache((char *)pc, (char *)pc + 4);
}

static uintptr_t brov_direct_fault_pc(void *ctx)
{
    return (uintptr_t)((ucontext_t *)ctx)->uc_mcontext.pc;
}

static void brov_direct_set_fault_pc(void *ctx, uintptr_t pc)
{
    ((ucontext_t *)ctx)->uc_mcontext.pc = pc;
}
