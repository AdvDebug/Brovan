/* Included at the end of the setjmp block of os-win32.h. The pair lives in
 * brovan_setjmp_win64.asm, which replaces qemu/util/setjmp-wrapper-win32.asm. */

#if defined(_M_X64)
int brov_setjmp(jmp_buf env);
__declspec(noreturn) void brov_longjmp(jmp_buf env, int value);

#undef setjmp
#define setjmp(env) brov_setjmp(env)
#undef siglongjmp
#define siglongjmp(env, val) brov_longjmp(env, val)
#endif
