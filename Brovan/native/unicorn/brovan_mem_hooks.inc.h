/* Included into qemu/include/exec/exec-all.h, just above uc_mem_hook_installed.
 *
 * That predicate answers "must guest writes to this page keep taking the slow
 * path?". notdirty_write() consults it before calling tlb_set_dirty(), which is
 * what upgrades a write TLB entry from TLB_NOTDIRTY to the inline fast path,
 * and tb_gen_code() consults it to undo that for pages that become code.
 *
 * It counted the fault-only hook types too. Those fire only from tlb_fill()
 * after an access has already missed or failed its permission check, which
 * cannot happen on a page that has a valid writable TLB entry - so they never
 * needed the slow path. Brovan registers exactly those two (they are how a
 * guest access violation is reported), which meant every store in every guest
 * program stayed on store_helper permanently: measured 6.3x slower than the
 * equivalent load, and the largest single cost in the emulator.
 *
 * Both callers must agree, so the narrowing lives here rather than at one call
 * site: tb_gen_code() has to restore dirty tracking for exactly the pages
 * notdirty_write() would have made fast, or self-modifying code stops being
 * detected.
 */
#ifndef BROVAN_MEM_HOOKS_H
#define BROVAN_MEM_HOOKS_H

static inline bool brov_mem_hook_needs_slow_path(struct uc_struct *uc, hwaddr paddr)
{
    return HOOK_EXISTS_BOUNDED(uc, UC_HOOK_MEM_READ, paddr) ||
           HOOK_EXISTS_BOUNDED(uc, UC_HOOK_MEM_READ_AFTER, paddr) ||
           HOOK_EXISTS_BOUNDED(uc, UC_HOOK_MEM_WRITE, paddr);
}

#endif
