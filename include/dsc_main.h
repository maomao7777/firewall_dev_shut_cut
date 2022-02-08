#ifndef _DSC_MAIN_H_
#define _DSC_MAIN_H_

#include <gconfig.h>
#include <linux/version.h>
#include <linux/major.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/sockios.h>
#include <linux/netdevice.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <__ostypes.h>
#include <dsc_debug.h>


#define T_NUM_OF_ELEMENTS(x) (sizeof(x)/sizeof(x[0]))

#define OS_NTOHS(_Val) \
                (ntohs(_Val))
#define OS_HTONS(_Val) \
                (htons(_Val))
#define OS_NTOHL(_Val) \
                (ntohl(_Val))
#define OS_HTONL(_Val) \
                (htonl(_Val))


#define PKT_HANDLER_PERIOD 32    //32 ticks, 32 * 10ms = 320ms

#define IN_IPV4_MCAST_GRP(ip) ((ip[0]&0xf0) == 0xe0)
#define IN_IPV6_MCAST_GRP(ip) ((ip[0]&0xff) == 0xff)

#define IS_IPV6_MULTICAST_PKT(mac) (mac[0]==0x33 && mac[1]==0x33)


#define IS_MULTICAST_PKT(mac) (mac[0]==0x01 && mac[1]==0x00 && mac[2]==0x5e)
#define IS_BROADCAST_PKT(mac) (mac[0]==0xff && mac[1]==0xff && mac[2]==0xff && mac[3]==0xff && mac[4]==0xff && mac[5]==0xff)


// Put platform dependent declaration here
// For example, linux type definition
typedef unsigned char           UINT8;
typedef unsigned short          UINT16;
//typedef unsigned long         UINT32;
typedef unsigned int            UINT32;
typedef unsigned long long      UINT64;
typedef unsigned int *          PUINT32;
typedef char                    INT8;
typedef short                   INT16;
typedef int                     INT32;
typedef long long               INT64;


enum
{
    STATUS_DSC_OK     = 1<<0,/*netdev_max_backlog = 100;*/
    STATUS_DSC_DROP   = 1<<1,/*CPU will not see this packet*/
    STATUS_DSC_SMALLQ = 1<<2,/*netdev_max_backlog = 200;*/
    STATUS_DSC_DROP_AND_FREE   = 1<<3,/*CPU will not see this packet and free this packet*/
};

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif
