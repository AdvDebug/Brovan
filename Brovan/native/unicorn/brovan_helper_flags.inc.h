/* Between a pair of these includes, a plain DEF_HELPER_n must touch no TCG global, read no guest memory
 * and raise nothing. The SSE helpers reach the XMM globals in env, but gen_sse calls them only behind sync_xmm. */
#ifdef BROV_HELPERS_TOUCH_NO_GLOBAL
#undef BROV_HELPERS_TOUCH_NO_GLOBAL
#else
#define BROV_HELPERS_TOUCH_NO_GLOBAL
#endif

#undef BROV_HELPER_FLAGS
#ifdef BROV_HELPERS_TOUCH_NO_GLOBAL
#define BROV_HELPER_FLAGS TCG_CALL_NO_RWG
#else
#define BROV_HELPER_FLAGS 0
#endif

#undef DEF_HELPER_1
#undef DEF_HELPER_2
#undef DEF_HELPER_3
#undef DEF_HELPER_4
#define DEF_HELPER_1(name, ret, t1) DEF_HELPER_FLAGS_1(name, BROV_HELPER_FLAGS, ret, t1)
#define DEF_HELPER_2(name, ret, t1, t2) DEF_HELPER_FLAGS_2(name, BROV_HELPER_FLAGS, ret, t1, t2)
#define DEF_HELPER_3(name, ret, t1, t2, t3) DEF_HELPER_FLAGS_3(name, BROV_HELPER_FLAGS, ret, t1, t2, t3)
#define DEF_HELPER_4(name, ret, t1, t2, t3, t4) DEF_HELPER_FLAGS_4(name, BROV_HELPER_FLAGS, ret, t1, t2, t3, t4)
