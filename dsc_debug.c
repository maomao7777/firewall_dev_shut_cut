/** 
 *   @file dsc_debug.c
 *   @brief dsc debug
 *   @author cfho
 *   @version 0.1
 *   @date  2012-04-11
 *   @bug none
 *   @warning none
*/
/** -------------------------------------------------------------------------
                          INCLUDE HEADER FILES                             
  -------------------------------------------------------------------------*/


#include <gconfig.h>
#include <__ostypes.h>
#include <linux/version.h>
#include <linux/major.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>                  /* for kmalloc() and kfree() */
#include <linux/sched.h>                 /* for struct wait_queue etc */
#include <linux/delay.h>                 /* guess what */
#include <linux/fs.h>                    /* struct file */
#include <linux/proc_fs.h>               /* support /proc */
#include <asm/uaccess.h>
#include <linux/sockios.h>
#include <linux/netdevice.h>             /* for struct net_device */

#include <dsc_main.h>
#include <dsc_config.h>
#include <dsc_debug.h>


 
#if CFG_ELX_DSC_DEBUG
void hex_dump(char *str, unsigned char *pSrcBufVA, unsigned int SrcBufLen)
{
        unsigned char *pt;
        int x;
 
        pt = pSrcBufVA;
        printk("%s: %p, len = %d\n",str,  pSrcBufVA, SrcBufLen);
        for (x=0; x<SrcBufLen; x++)
        {
                if (x % 16 == 0) 
                        printk("0x%04x : ", x);
                printk("%02x ", ((unsigned char)pt[x]));
                if (x%16 == 15) printk("\n");
        }
        printk("\n");
}
/*****************************************************************************/
/**
*  @brief miscHexDump3
*  @param T_VOID
*  @return T_VOID
*/
T_VOID miscHexDump3(unsigned int offset, const unsigned char *data,int buf_siz)
{
        size_t i, j, jmax;
        int c;
        char buf[100];

        if(data == NULL) buf_siz = 0;

        for(i = 0; i < buf_siz; i += 0x10)
        {
                sprintf(buf,"%08x: ", (unsigned int)(i + offset));
                jmax = buf_siz - i;
                jmax = jmax > 16 ? 16 : jmax;

                for(j = 0; j < jmax; j++)
                {
                        if((j % 2) == 1)
                        {
                                sprintf(buf + strlen(buf),"%02x ", (unsigned int)data[i+j]);
                        }
                        else
                        {
                                sprintf(buf + strlen(buf),"%02x", (unsigned int)data[i+j]);
                        }
                }
                for(; j < 16; j++)
                {
                        if((j % 2) == 1)
                        {
                                sprintf(buf + strlen(buf),"   ");
                        }
                        else
                        {
                                sprintf(buf + strlen(buf), "  ");
                        }
                }
                sprintf(buf + strlen(buf),  " ");
                for(j = 0; j < jmax; j++)
                {
                        c = data[i+j];
                        c = c < 32 || c >= 127 ? '.' : c;
                        sprintf(buf + strlen(buf),  "%c", c);
                }
                printk("%s\n", buf);
        }
}
/*****************************************************************************/
/**
*  @brief skb_dump
*  @param char *name
*  @param struct sk_buff* sk
*  @return T_VOID
*/
void skb_dump(char *name,struct sk_buff* sk) 
{
        unsigned int i;

        printk("[%s] skb_dump: from %s with len %d (%d) headroom=%d tailroom=%d\n",
			   name, sk->dev?sk->dev->name:"ip stack",sk->len,sk->truesize,
                skb_headroom(sk),skb_tailroom(sk));

        //for(i=(unsigned int)sk->head;i<=(unsigned int)sk->tail;i++) {
        for(i=(unsigned int)sk->head;i<=(unsigned int)sk->data+64;i++) {
                if((i % 20) == 0)
                        printk("\n");
                if(i==(unsigned int)sk->data) printk("{");
                if(i==(unsigned int)sk->transport_header) printk("#");
                if(i==(unsigned int)sk->network_header) printk("|");
                if(i==(unsigned int)sk->mac_header) printk("*");
                printk("%02X-",*((unsigned char*)i));
                if(i==(unsigned int)sk->tail) printk("}");
        }
        printk("\n<================================================>\n\n");
}
#endif

 
/** ***********************  END  ********************************************/

