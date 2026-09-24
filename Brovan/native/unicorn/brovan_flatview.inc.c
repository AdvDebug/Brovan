/* Appended to qemu/softmmu/memory.c.
 *
 * Adding a region re-rendered the whole memory topology and rebuilt its dispatch
 * tree, so mapping guest memory cost O(live regions) and a guest that holds many
 * mappings paid it on every commit. A region that lands in a gap of the current
 * view can instead be inserted into that view, with only its own section added to
 * the dispatch.
 *
 * Anything the insert cannot reason about locally - an overlap, a container, a
 * view rooted below the system region - returns false and takes the general path,
 * which still re-renders.
 *
 * The commit listeners are not called on this path. That is safe because the only
 * one registered caches fv->dispatch, which this mutates in place rather than
 * replacing, and does a TLB flush that this issues itself before returning.
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

static bool brov_flatview_add(MemoryRegion *mr)
{
    struct uc_struct *uc;
    AddressSpace *as;
    FlatView *fv;
    FlatRange fr;
    AddrRange r;
    MemoryRegionSection mrs;
    unsigned lo, hi, pos;

    if (!mr || !mr->uc) {
        return false;
    }

    uc = mr->uc;

    if (!uc->memory_region_update_pending || !uc->system_memory || !uc->flat_views) {
        return false;
    }

    /* RAM only: an MMIO region reaches the dispatch through the subpage path and is
     * split by different code, and there are only ever a handful of them. */
    if (!mr->ram || !mr->enabled || !mr->terminates ||
        mr->container != uc->system_memory || uc->system_memory->addr != 0 ||
        uc->system_memory->readonly || !QTAILQ_EMPTY(&mr->subregions)) {
        return false;
    }

    as = memory_region_to_address_space(mr);
    if (!as || as->root != uc->system_memory ||
        memory_region_get_flatview_root(as->root) != uc->system_memory) {
        return false;
    }

    fv = address_space_to_flatview(as);
    if (!fv || fv->root != uc->system_memory ||
        g_hash_table_lookup(uc->flat_views, uc->system_memory) != fv) {
        return false;
    }

    r = addrrange_make(int128_make64(mr->addr), mr->size);

    lo = 0;
    hi = fv->nr;
    while (lo < hi) {
        unsigned mid = lo + ((hi - lo) >> 1);

        if (int128_le(addrrange_end(fv->ranges[mid].addr), r.start)) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    pos = lo;

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

