/* Included into qemu/accel/tcg/cputlb.c, after its own includes.
 *
 * notdirty_write() decides whether a guest store may be promoted back onto the
 * inline TLB fast path. Until that happens every store to the page goes through
 * store_helper, which is a C call - measured 6.3x the cost of the equivalent
 * load, and the single largest cost in the emulator for ordinary guest code.
 *
 * See brovan_mem_hooks.inc.h for why the fault-only hook types must not count
 * towards "a hook needs to see this store".
 *
 * A promoted entry outlives the decision that produced it, so uc_mem_protect()
 * now flushes the TLB. Only a change in *writability* reaches tcg_commit's
 * flush (via memory_region_set_readonly), so dropping and restoring EXEC on a
 * page that stayed writable used to leave a promoted entry in place, and the
 * next store of new instructions skipped TB invalidation - caught by the
 * exec-off/on case in the SMC test.
 */
#ifndef BROVAN_NOTDIRTY_H
#define BROVAN_NOTDIRTY_H

static inline bool brov_notdirty_allowed(CPUState *cpu, vaddr mem_vaddr,
                                         CPUTLBEntry *tlbe)
{
#ifdef TARGET_ARM
    /* TARGET_PAGE_MASK reads uc->init_target_page on this target. */
    struct uc_struct *uc = cpu->uc;
#endif
    hwaddr pa = tlbe->paddr | (mem_vaddr & ~TARGET_PAGE_MASK);
    MemoryRegion *mr = cpu->uc->memory_mapping(cpu->uc, pa);

    if (!mr || tlbe->addr_write == (target_ulong)-1) {
        return false;
    }
    if (mr->priority < cpu->uc->snapshot_level) {
        return false;
    }
    /* A page that can hold translated code keeps dirty tracking, so that a store
     * into it still reaches tb_invalidate_phys_page_fast.
     *
     * The region's own permission is the test, not tlbe->addr_code. Brovan runs
     * the guest with paging off, and target/i386 hands tlb_fill
     * PAGE_READ|PAGE_WRITE|PAGE_EXEC for every page in that mode, so addr_code
     * is never -1 and that gate rejected the entire address space. which is
     * what kept every guest store on store_helper. The region permission is also
     * the condition guarding the tb_invalidate_phys_page_fast call above, and no
     * TB can exist for a region that is not executable, because an instruction
     * fetch from one faults. */
    if ((mr->perms & UC_PROT_EXEC) != 0) {
        return false;
    }
    return !brov_mem_hook_needs_slow_path(cpu->uc, pa);
}

static inline bool brov_notdirty_promote(CPUState *cpu, vaddr mem_vaddr,
                                         CPUTLBEntry *tlbe)
{
    static int disabled = -1;

    if (disabled < 0) {
        /* Kill switch: this decides whether a guest store may skip
         * store_helper, so keep a way back to Unicorn's behaviour. */
        disabled = getenv("BROVAN_NO_STORE_FAST") != NULL;
    }
    if (disabled) {
        return false;
    }

    return brov_notdirty_allowed(cpu, mem_vaddr, tlbe);
}

/* A memory hook that declines an access leaves the loop from inside the helper,
 * with the PC back on the faulting instruction. A hook-free run emits no
 * check_exit_request after an access, so exit_request alone would not stop it.
 * skip_sync_pc_on_exit is ignored here. An earlier PC write in the slice can
 * leave it set, and honouring it would keep a stale lazy eip. */
static inline void brov_fault_exit(struct uc_struct *uc, uintptr_t retaddr)
{
    cpu_exit(uc->cpu);
    if (uc->nested_level > 0 && !uc->cpu->stopped) {
        cpu_loop_exit_restore(uc->cpu, retaddr);
    }
}

#endif
