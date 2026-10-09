/* Appended to qemu/softmmu/memory.c.
 *
 * The general path re-renders the whole memory topology and rebuilds its
 * dispatch tree, which costs O(live regions) on every commit. A region that lands
 * in a gap of the current view is inserted into that view instead, with only its
 * own section added to the dispatch.
 *
 * Anything the insert cannot reason about locally - an overlap, a container, a
 * view rooted below the system region - returns false and takes the general path,
 * which still re-renders.
 *
 * The commit listeners are not called on this path. The only one registered
 * caches fv->dispatch, which this mutates in place rather than replacing, and does
 * a TLB flush that this issues itself before returning.
 *
 * brov_dispatch_compact keeps the one view this mutates out of the compactor: a
 * compacted radix tree cannot take an incremental insert. Every other dispatch,
 * including every other address space, is still compacted as usual. */

/* render_memory_region is O(n^2) in the region count. A root of non-overlapping
 * leaves is uc->mapped_blocks, already in address order. mapped_blocks can still
 * hold a region that is being unmapped, so the counts must match. */
static bool brov_render_flat(FlatView *view, MemoryRegion *root)
{
    struct uc_struct *uc = root->uc;
    MemoryRegion *child;
    Int128 end = int128_zero();
    unsigned leaves = 0;
    unsigned found = 0;
    uint32_t i;
    static int disabled = -1;

    if (disabled < 0) {
        disabled = getenv("BROVAN_NO_FLAT_RENDER") != NULL;
    }
    if (disabled || !uc || root != uc->system_memory || !root->enabled || root->terminates ||
        root->readonly || root->addr != 0 || view->nr != 0) {
        return false;
    }

    QTAILQ_FOREACH(child, &root->subregions, subregions_link) {
        if (!child->enabled) {
            continue;
        }
        if (!child->terminates || !QTAILQ_EMPTY(&child->subregions)) {
            return false;
        }
        leaves++;
    }

    for (i = 0; i < uc->mapped_block_count; i++) {
        MemoryRegion *mr = uc->mapped_blocks[i];

        if (mr->container != root || !mr->enabled) {
            continue;
        }
        if (!int128_nz(mr->size) || int128_lt(int128_make64(mr->addr), end)) {
            return false;
        }
        end = int128_add(int128_make64(mr->addr), mr->size);
        if (int128_gt(end, root->size)) {
            return false;
        }
        found++;
    }

    if (found != leaves) {
        return false;
    }

    for (i = 0; i < uc->mapped_block_count; i++) {
        MemoryRegion *mr = uc->mapped_blocks[i];
        FlatRange fr;

        if (mr->container != root || !mr->enabled) {
            continue;
        }
        fr.mr = mr;
        fr.offset_in_region = 0;
        fr.addr = addrrange_make(int128_make64(mr->addr), mr->size);
        fr.readonly = mr->readonly;
        flatview_insert(view, view->nr, &fr);
    }
    return true;
}

static void brov_dispatch_compact(FlatView *fv)
{
    MemoryRegion *root = fv->root;

    if (root && root->uc && root == root->uc->system_memory) {
        return;
    }

    address_space_dispatch_compact(fv->dispatch);
}

static FlatView *brov_system_view(MemoryRegion *mr)
{
    struct uc_struct *uc = mr->uc;
    AddressSpace *as;
    FlatView *fv;

    if (!uc->system_memory || !uc->flat_views) {
        return NULL;
    }

    /* RAM only: an MMIO region reaches the dispatch through the subpage path and is
     * split by different code, and there are only ever a handful of them. */
    if (!mr->ram || !mr->enabled || !mr->terminates ||
        mr->container != uc->system_memory || uc->system_memory->addr != 0 ||
        uc->system_memory->readonly || !QTAILQ_EMPTY(&mr->subregions)) {
        return NULL;
    }

    as = memory_region_to_address_space(mr);
    if (!as || as->root != uc->system_memory ||
        memory_region_get_flatview_root(as->root) != uc->system_memory) {
        return NULL;
    }

    fv = address_space_to_flatview(as);
    if (!fv || fv->root != uc->system_memory ||
        g_hash_table_lookup(uc->flat_views, uc->system_memory) != fv) {
        return NULL;
    }

    return fv;
}

static unsigned brov_range_pos(FlatView *fv, AddrRange r)
{
    unsigned lo = 0;
    unsigned hi = fv->nr;

    while (lo < hi) {
        unsigned mid = lo + ((hi - lo) >> 1);

        if (int128_le(addrrange_end(fv->ranges[mid].addr), r.start)) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static bool brov_flatview_add(MemoryRegion *mr)
{
    struct uc_struct *uc;
    FlatView *fv;
    FlatRange fr;
    AddrRange r;
    MemoryRegionSection mrs;
    unsigned pos;

    if (!mr || !mr->uc || !mr->uc->memory_region_update_pending) {
        return false;
    }

    uc = mr->uc;
    fv = brov_system_view(mr);
    if (!fv) {
        return false;
    }

    r = addrrange_make(int128_make64(mr->addr), mr->size);
    pos = brov_range_pos(fv, r);

    if (pos < fv->nr && addrrange_intersects(fv->ranges[pos].addr, r)) {
        return false;
    }

    fr.mr = mr;
    fr.offset_in_region = 0;
    fr.addr = r;
    fr.readonly = mr->readonly;

    flatview_insert(fv, pos, &fr);

    mrs = section_from_flat_range(&fv->ranges[pos], fv);
    flatview_add_to_dispatch(uc, fv, &mrs);

    /* memory_region_add_subregion is public API, so do not rely on the caller: the
     * commit listener skipped here is what normally flushes the TLB. */
    if (uc->cpu) {
        tlb_flush(uc->cpu);
    }

    uc->memory_region_update_pending = false;
    return true;
}

/* A readonly flip changes the range, the region and its dispatch section in place
 * instead of rebuilding the dispatch. uc_mem_protect flushes the TLB once after its loop. */
static bool brov_set_readonly_in_place(MemoryRegion *mr, bool readonly)
{
    struct uc_struct *uc;
    FlatView *fv;
    MemoryRegionSection *section;
    AddrRange r;
    hwaddr xlat, plen;
    unsigned pos;
    int prot = 0;
    static int disabled = -1;

    if (disabled < 0) {
        disabled = getenv("BROVAN_NO_READONLY_IN_PLACE") != NULL;
    }
    if (disabled || !mr || !mr->uc || mr->readonly == readonly) {
        return false;
    }

    uc = mr->uc;
    if (!uc->cpu || !uc->cpu->cpu_ases || (mr->addr & uc->target_page_align) != 0 ||
        (int128_getlo(mr->size) & uc->target_page_align) != 0) {
        return false;
    }

    fv = brov_system_view(mr);
    if (!fv) {
        return false;
    }

    r = addrrange_make(int128_make64(mr->addr), mr->size);
    pos = brov_range_pos(fv, r);
    if (pos >= fv->nr || fv->ranges[pos].mr != mr || fv->ranges[pos].offset_in_region != 0 ||
        !addrrange_equal(fv->ranges[pos].addr, r)) {
        return false;
    }

    plen = uc->target_page_size;
    section = address_space_translate_for_iotlb(uc->cpu, 0, mr->addr, &xlat, &plen,
                                                MEMTXATTRS_UNSPECIFIED, &prot);
    if (section->mr != mr || section->offset_within_address_space != mr->addr ||
        section->offset_within_region != 0 || !int128_eq(section->size, mr->size)) {
        return false;
    }

    mr->readonly = readonly;
    fv->ranges[pos].readonly = readonly;
    section->readonly = readonly;

    if (!uc->brov_protect_batch) {
        tlb_flush(uc->cpu);
    }
    return true;
}

