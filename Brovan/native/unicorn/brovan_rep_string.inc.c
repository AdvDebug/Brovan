/* A page that tlb_vaddr_to_host refuses gives no run, and the translated loop after the call moves
 * one element through the slow path, so a fault still names the exact element. */

/* A run would count as one block in the instruction budget, so it is charged by its size. */
#define BROV_REP_BUDGET_SHIFT 4

static size_t brov_rep_run_bytes(target_ulong first, target_ulong second,
                                 target_ulong count, unsigned shift)
{
    target_ulong bytes = TARGET_PAGE_SIZE - (first & ~TARGET_PAGE_MASK);
    target_ulong room = TARGET_PAGE_SIZE - (second & ~TARGET_PAGE_MASK);

    if (bytes > room) {
        bytes = room;
    }
    if ((bytes >> shift) > count) {
        bytes = count << shift;
    }
    return (size_t)(bytes & ~(((target_ulong)1 << shift) - 1));
}

static void brov_rep_charge(CPUX86State *env, size_t bytes)
{
    CPUState *cs = env_cpu(env);

    if (cs->uc->brov_budget_mode) {
        cpu_neg(cs)->brov_insn_budget -= (int32_t)(bytes >> BROV_REP_BUDGET_SHIFT);
    }
}

void helper_brov_rep_movs(CPUX86State *env, uint32_t shift, uint32_t wide)
{
    target_ulong mask = wide ? (target_ulong)-1 : (target_ulong)0xffffffffu;
    target_ulong count = env->regs[R_ECX] & mask;
    target_ulong src = env->regs[R_ESI] & mask;
    target_ulong dst = env->regs[R_EDI] & mask;
    uint8_t *host_src, *host_dst;
    size_t bytes, step, i;
    int mmu_idx;

    if (count == 0 || env->df != 1 || tcg_uc_has_hookmem(env->uc->tcg_ctx)) {
        return;
    }

    bytes = brov_rep_run_bytes(src, dst, count, shift);
    if (bytes == 0) {
        return;
    }

    mmu_idx = cpu_mmu_index(env, false);
    host_src = tlb_vaddr_to_host(env, src, MMU_DATA_LOAD, mmu_idx);
    if (!host_src) {
        return;
    }
    host_dst = tlb_vaddr_to_host(env, dst, MMU_DATA_STORE, mmu_idx);
    if (!host_dst) {
        return;
    }

    if ((uintptr_t)host_dst - (uintptr_t)host_src >= bytes) {
        memmove(host_dst, host_src, bytes);
    } else if (host_dst != host_src) {
        /* The destination starts inside the source run, so later elements read what earlier ones wrote. */
        step = (size_t)1 << shift;
        for (i = 0; i < bytes; i += step) {
            uint64_t element = 0;

            memcpy(&element, host_src + i, step);
            memcpy(host_dst + i, &element, step);
        }
    }

    env->regs[R_ESI] = (src + bytes) & mask;
    env->regs[R_EDI] = (dst + bytes) & mask;
    env->regs[R_ECX] = count - (bytes >> shift);
    brov_rep_charge(env, bytes);
}

void helper_brov_rep_stos(CPUX86State *env, uint32_t shift, uint32_t wide)
{
    target_ulong mask = wide ? (target_ulong)-1 : (target_ulong)0xffffffffu;
    target_ulong count = env->regs[R_ECX] & mask;
    target_ulong dst = env->regs[R_EDI] & mask;
    uint64_t value = env->regs[R_EAX];
    uint8_t *host_dst;
    size_t bytes, i;

    if (count == 0 || env->df != 1 || tcg_uc_has_hookmem(env->uc->tcg_ctx)) {
        return;
    }

    bytes = brov_rep_run_bytes(dst, dst, count, shift);
    if (bytes == 0) {
        return;
    }

    host_dst = tlb_vaddr_to_host(env, dst, MMU_DATA_STORE, cpu_mmu_index(env, false));
    if (!host_dst) {
        return;
    }

    switch (shift) {
    case 0:
        memset(host_dst, (uint8_t)value, bytes);
        break;
    case 1:
        for (i = 0; i < bytes; i += 2) {
            stw_le_p(host_dst + i, (uint16_t)value);
        }
        break;
    case 2:
        for (i = 0; i < bytes; i += 4) {
            stl_le_p(host_dst + i, (uint32_t)value);
        }
        break;
    default:
        for (i = 0; i < bytes; i += 8) {
            stq_le_p(host_dst + i, value);
        }
        break;
    }

    env->regs[R_EDI] = (dst + bytes) & mask;
    env->regs[R_ECX] = count - (bytes >> shift);
    brov_rep_charge(env, bytes);
}
