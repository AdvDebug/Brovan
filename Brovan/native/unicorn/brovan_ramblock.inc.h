/* Included by qemu/exec.c.
 *
 * Two list walks in the RAM block allocator are O(live blocks), and every guest
 * mapping is a block, so a guest that holds thousands of mappings pays for them on
 * every commit.
 *
 * ram_block_add keeps the list ordered from biggest to smallest and finds the
 * insertion point by walking it. A block no larger than the current tail belongs
 * at the tail, which the caller already reaches without walking. qemu_ram_free
 * drops ram_list.last_block, so recover the tail once per free rather than falling
 * back to the walk on every later map.
 *
 * find_ram_offset picks the smallest gap in the offset space that fits, and once
 * any block has been freed it looks for the block nearest each candidate by
 * scanning the whole list again, which is O(blocks squared). Sorting the starts
 * once and binary searching them gives the same answer. The starts buffer lives on
 * uc and only grows, so the hot path holds no per-call allocation. */

#include "qemu/bitops.h"

static inline bool brov_ramblock_needs_sort_walk(struct uc_struct *uc, RAMBlock *new_block)
{
    RAMBlock *tail = uc->ram_list.last_block;

    if (!tail) {
        RAMBlock *block;

        RAMBLOCK_FOREACH(block) {
            tail = block;
        }

        uc->ram_list.last_block = tail;
    }

    return !tail || tail->max_length < new_block->max_length;
}

static int brov_ram_addr_cmp(const void *a, const void *b)
{
    ram_addr_t left = *(const ram_addr_t *)a;
    ram_addr_t right = *(const ram_addr_t *)b;

    if (left < right) {
        return -1;
    }

    return left > right ? 1 : 0;
}

static bool brov_find_ram_offset(struct uc_struct *uc, ram_addr_t size, ram_addr_t *result)
{
    RAMBlock *block;
    ram_addr_t *starts;
    ram_addr_t offset = RAM_ADDR_MAX;
    ram_addr_t mingap = RAM_ADDR_MAX;
    unsigned count = 0;
    unsigned i = 0;

    /* Before the first free the offsets only grow, and the caller has an O(1) answer
     * for that case. */
    if (!uc->ram_list.freed) {
        return false;
    }

    RAMBLOCK_FOREACH(block) {
        count++;
    }

    if (count == 0) {
        return false;
    }

    if (count > uc->brov_ram_starts_cap) {
        uc->brov_ram_starts = g_realloc(uc->brov_ram_starts, count * sizeof(ram_addr_t));
        uc->brov_ram_starts_cap = count;
    }

    starts = (ram_addr_t *)uc->brov_ram_starts;

    RAMBLOCK_FOREACH(block) {
        starts[i++] = block->offset;
    }

    qsort(starts, count, sizeof(*starts), brov_ram_addr_cmp);

    RAMBLOCK_FOREACH(block) {
        ram_addr_t candidate = ROUND_UP(block->offset + block->max_length,
                                        BITS_PER_LONG << TARGET_PAGE_BITS);
        ram_addr_t next = RAM_ADDR_MAX;
        unsigned lo = 0;
        unsigned hi = count;

        while (lo < hi) {
            unsigned mid = lo + ((hi - lo) >> 1);

            if (starts[mid] < candidate) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        if (lo < count) {
            next = starts[lo];
        }

        if (next - candidate >= size && next - candidate < mingap) {
            offset = candidate;
            mingap = next - candidate;
        }
    }

    if (offset == RAM_ADDR_MAX) {
        return false;
    }

    *result = offset;
    return true;
}
