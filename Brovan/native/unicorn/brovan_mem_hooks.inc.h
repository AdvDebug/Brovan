/* Included into qemu/include/exec/exec-all.h, just above uc_mem_hook_installed.
 *
 * That predicate answers "must guest writes to this page keep taking the slow
 * path?". notdirty_write() consults it before calling tlb_set_dirty(), which is
 * what upgrades a write TLB entry from TLB_NOTDIRTY to the inline fast path,
 * and tb_gen_code() consults it to undo that for pages that become code.
 *
 * The fault-only hook types do not count. They fire only from tlb_fill() after
 * an access has missed or failed its permission check, which cannot happen on a
 * page that has a valid writable TLB entry.
 *
 * Both callers must agree, so the rule lives here rather than at one call site.
 * tb_gen_code() has to restore dirty tracking for exactly the pages
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
