/** 
 *   @file captive_portal_handler
 *   @brief captive_portal_handler
 *   @author
 *   @version
 *   @date
 *   @bug
 *   @warning
*/
/** -------------------------------------------------------------------------
                          INCLUDE HEADER FILES
  -------------------------------------------------------------------------*/
#include <dsc_main.h>
#include <dsc_config.h>
#include <dsc_debug.h>
/** -------------------------------------------------------------------------
                          DEFINITIONS
  -------------------------------------------------------------------------*/
#define dbg_printk(x...)   printk(x)

/* Forward IP 1 -> IP 2 */
#define SAMPLE_IP1   0x08080808
#define SAMPLE_IP2   0x0102a8c0

/** -------------------------------------------------------------------------
                          VARIABLES
  -------------------------------------------------------------------------*/

/** -------------------------------------------------------------------------
                          FUNCTIONS
  -------------------------------------------------------------------------*/
#if 0
static void skb_dump0(char *name,struct sk_buff* sk) {
        unsigned int i;

        printk("[%s] skb_dump: from %s with len %d (%d) headroom=%d tailroom=%d\n",
			   name, sk->dev?sk->dev->name:"ip stack",sk->len,sk->truesize,
                skb_headroom(sk),skb_tailroom(sk));

        for(i=(unsigned int)sk->head;i<=(unsigned int)sk->tail;i++) {
        // for(i=(unsigned int)sk->head;i<=(unsigned int)sk->data+64;i++) {
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
/*****************************************************************************/
/**
*  @brief sample_l2_rx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT sample_l2_rx_handler(struct sk_buff *skb)
{
    unsigned char *data = skb->data;
    struct ethhdr *eth_header = (struct ethhdr *)data;
    struct iphdr *ip_header;
    struct arpheader *arp_header;
    struct tcphdr *tcp_header;
    
    dbg_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    dbg_printk("%s[%d], %s\n", __FUNCTION__, __LINE__, skb->dev->name);
    dbg_printk("%s[%d], %x\n", __FUNCTION__, __LINE__, eth_header->h_proto);

    dbg_printk("%s[%d], %x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__, eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2], eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
    dbg_printk("%s[%d], %x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__, eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2], eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);

    // skb_dump0(__FUNCTION__, skb);
    
    if(eth_header->h_proto == htons(ETH_P_IP))
    {
        ip_header = (struct iphdr*)(data+ETH_HLEN);
        dbg_printk("%s[%d], ip_header->daddr = %x\n", __FUNCTION__, __LINE__, ip_header->daddr);
        dbg_printk("%s[%d], ip_header->saddr = %x\n", __FUNCTION__, __LINE__, ip_header->saddr);
        dbg_printk("%s[%d], ip_header->protocol = %x\n", __FUNCTION__, __LINE__, ip_header->protocol);  
#if 0
        if(ip_header->daddr==SAMPLE_IP1)
        {
            ip_header->daddr = SAMPLE_IP2;
            compute_ip_checksum(ip_header);
        }
#endif
    }else if(eth_header->h_proto == htons(ETH_P_ARP))
    {
        arp_header = (struct arpheader*)(data+ETH_HLEN);
        dbg_printk("%s[%d]\n", __FUNCTION__, __LINE__);
    }

	return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief sample_l2_tx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT sample_l2_tx_handler(struct sk_buff *skb)
{
    unsigned char *data = skb->data;
    struct ethhdr *eth_header = (struct ethhdr *)data;
    struct iphdr *ip_header;
    struct arpheader *arp_header;
    struct tcphdr *tcp_header;
    
    dbg_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    dbg_printk("%s[%d], %s\n", __FUNCTION__, __LINE__, skb->dev->name);
    dbg_printk("%s[%d], %x\n", __FUNCTION__, __LINE__, eth_header->h_proto);

    dbg_printk("%s[%d], %x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__, eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2], eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
    dbg_printk("%s[%d], %x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__, eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2], eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);

    // skb_dump0(__FUNCTION__, skb);
    
    if(eth_header->h_proto == htons(ETH_P_IP))
    {
        ip_header = (struct iphdr*)(data+ETH_HLEN);
        dbg_printk("%s[%d], ip_header->daddr = %x\n", __FUNCTION__, __LINE__, ip_header->daddr);
        dbg_printk("%s[%d], ip_header->saddr = %x\n", __FUNCTION__, __LINE__, ip_header->saddr);
        dbg_printk("%s[%d], ip_header->protocol = %x\n", __FUNCTION__, __LINE__, ip_header->protocol);  
#if 0
        if(ip_header->saddr==SAMPLE_IP2)
        {
            ip_header->saddr = SAMPLE_IP1;
        }
#endif
    }else if(eth_header->h_proto == htons(ETH_P_ARP))
    {
        arp_header = (struct arpheader*)(data+ETH_HLEN);
        dbg_printk("%s[%d]\n", __FUNCTION__, __LINE__);
    }

	return STATUS_DSC_OK;
	return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief captive_portal_handler_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT sample_l2_handler_init_driver(T_VOID)
{
	dbg_printk("Start %s\n", __FUNCTION__);
	return 0;
}

/*****************************************************************************/
/**
*  @brief captive_portal_handler_cleanup_driver
*  @param T_VOID
*  @return T_VOID
*/
T_VOID sample_l2_handler_cleanup_driver(T_VOID)
{
	dbg_printk("Clean up %s\n", __FUNCTION__);
}

/** ***********************  END  ********************************************/