/* Included near the top of qemu/accel/tcg/translate-all.c.
 *
 * The definitions live in brovan_uc_tcg.inc.c, appended to the end of the same
 * file, because they need that file's statics (tb_page_add, tb_phys_invalidate,
 * page_lock_pair). translate-all.c is compiled once per target, so everything
 * here is static and reached from outside only through uc->brov. */
#ifndef BROVAN_UC_TCG_DECLS_H
#define BROVAN_UC_TCG_DECLS_H

static bool brov_try_alloc_code_gen_buffer(struct uc_struct *uc, size_t tb_size);
static bool brov_owns_code_gen_buffer(struct uc_struct *uc);
static void brov_install(struct uc_struct *uc);

#endif
