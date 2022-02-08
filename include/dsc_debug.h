#ifndef _DSC_DEBUG_H
#define _DSC_DEBUG_H

#include <linux/netdevice.h>             /* for struct net_device */
#include "dsc_main.h"
#if CFG_ELX_DSC_DEBUG
void miscHexDump3(unsigned int offset, const unsigned char *data,int buf_siz);
void hex_dump(char *str, unsigned char *pSrcBufVA, unsigned int SrcBufLen);
void skb_dump(char *name,struct sk_buff* sk);
#else
#define miscHexDump3(x...) do{}while(0)
#define hex_dump(x...) do{}while(0)
#define skb_dump(x...) do{}while(0)
#endif
#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

 

#endif
