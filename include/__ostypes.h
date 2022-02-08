#ifndef __OSTYPES_H
#define __OSTYPES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void            T_VOID;
typedef int             T_BOOL;
typedef char            T_CHAR;
typedef unsigned char   T_UCHAR;
typedef int             T_INT;
typedef unsigned char   T_UINT8;
typedef unsigned short  T_UINT16;
typedef unsigned int    T_UINT32;
typedef signed char     T_INT8;
typedef signed short    T_INT16;
typedef signed int      T_INT32;
typedef unsigned long   T_ULONG;
typedef unsigned long long T_UINT64;

typedef unsigned long   T_IPADDR;
typedef T_UCHAR         T_MACADDR[6];

#ifndef TRUE
#define TRUE (1)
#define FALSE (!TRUE)
#endif

#ifndef ERROR
#define OK 0
#define ERROR (-1)
#endif


#ifndef NULL
#define NULL 0
#endif

#define T_ETHER_ADDRLEN (6)


#if (__GNUC__ == 4 && __GNUC_MINOR__ < 1) || (__GNUC__ < 4)
#define __S_ATTRIBUTE_PACKED__    
#define __ATTRIBUTE_PACKED__      __attribute__ ((packed))
#else
#define __S_ATTRIBUTE_PACKED__    __attribute__ ((packed))
#define __ATTRIBUTE_PACKED__      
#endif


#ifdef __cplusplus
}
#endif 

#endif
