#if defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
#else
    #ifndef _OS_BYTE_ORDER_H
    #define _OS_BYTE_ORDER_H 1
    #include <byteswap.h>

    #define OSSwapInt32(x) __bswap_32(x)
    #define _OSSwapInt64 __bswap_64

    #endif // _OS_BYTE_ORDER_H
#endif // defined(__APPLE__)
