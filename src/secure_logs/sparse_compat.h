#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#ifndef __must_hold
#define __must_hold(x)
#endif
#ifndef __acquires
#define __acquires(x)
#endif
#ifndef __releases
#define __releases(x)
#endif
#endif

