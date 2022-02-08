/** 
 *   @file test_handler
 *   @brief test_handler
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

/* Forward Port 1 -> Port 2 */
#define SAMPLE_PORT1 22222
#define SAMPLE_PORT2 80

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

extern T_VOID compute_ip_checksum(struct iphdr* iphdrp);
extern T_VOID compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload);

/*****************************************************************************/
/**
*  @brief sample_l3_rx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT sample_l3_rx_handler(struct sk_buff *skb)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    unsigned char src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
    UINT16 dst_port = 0, src_port = 0;
    // struct net_device *dev;
    dbg_printk("-------------------------\n");
    dbg_printk("%s[%d], %s\n", __FUNCTION__, __LINE__, skb->dev->name);
    dbg_printk("%s[%d], %x\n", __FUNCTION__, __LINE__, skb->protocol);
    
    // skb_dump0(__FUNCTION__, skb);
    
    if(skb->protocol == htons(ETH_P_IP))
    {
        ip_header = (struct iphdr *)skb_network_header(skb);
        
        dbg_printk("%s[%d], ip_header->daddr = %x\n", __FUNCTION__, __LINE__, ip_header->daddr);
        dbg_printk("%s[%d], ip_header->saddr = %x\n", __FUNCTION__, __LINE__, ip_header->saddr);
        dbg_printk("%s[%d], ip_header->protocol = %x\n", __FUNCTION__, __LINE__, ip_header->protocol);        

#if 1
        if(ip_header->daddr==SAMPLE_IP1)
        {
            ip_header->daddr = SAMPLE_IP2;
            compute_ip_checksum(ip_header);
        }
#endif

        if(ip_header->protocol == IPPROTO_TCP)
        {        
            dbg_printk("%s[%d]\n", __FUNCTION__, __LINE__);
    
            tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl); //this fixed the problem
        
            src_port = htons((unsigned short int) tcp_header->source); //sport now has the source port
            dst_port = htons((unsigned short int) tcp_header->dest);   //dport now has the dest port
            
            dbg_printk("%s[%d], src_port = %d\n", __FUNCTION__, __LINE__, src_port);
            dbg_printk("%s[%d], dst_port = %d\n", __FUNCTION__, __LINE__, dst_port);
    
            if(dst_port==SAMPLE_PORT1)
            {
                dbg_printk("%s[%d]\n", __FUNCTION__, __LINE__);
                tcp_header->dest = OS_NTOHS(SAMPLE_PORT2);
                compute_tcp_checksum(ip_header, tcp_header);     
                // skb->ip_summed = CHECKSUM_COMPLETE;    
            }
        }
    }
    
    return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief sample_l3_tx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT sample_l3_tx_handler(struct sk_buff *skb)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    unsigned char src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
    UINT16 dst_port = 0, src_port = 0;
    // struct net_device *dev;
    dbg_printk("-------------------------\n");
    dbg_printk("%s[%d], %s\n", __FUNCTION__, __LINE__, skb->dev->name);
    dbg_printk("%s[%d], %x\n", __FUNCTION__, __LINE__, skb->protocol);
    
    // skb_dump0(__FUNCTION__, skb);
    
    if(skb->protocol == htons(ETH_P_IP))
    {
        ip_header = (struct iphdr *)skb_network_header(skb);
        
        dbg_printk("%s[%d], ip_header->daddr = %x\n", __FUNCTION__, __LINE__, ip_header->daddr);
        dbg_printk("%s[%d], ip_header->saddr = %x\n", __FUNCTION__, __LINE__, ip_header->saddr);
        dbg_printk("%s[%d], ip_header->protocol = %x\n", __FUNCTION__, __LINE__, ip_header->protocol);  

#if 1
        if(ip_header->saddr==SAMPLE_IP2)
        {
            ip_header->saddr = SAMPLE_IP1;
        }
#endif                
        if(ip_header->protocol == IPPROTO_TCP)
        {    
            tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
        
            src_port = htons((unsigned short int) tcp_header->source);
            dst_port = htons((unsigned short int) tcp_header->dest);
            
            dbg_printk("%s[%d], src_port = %d, dst_port = %d\n", __FUNCTION__, __LINE__, src_port, dst_port);
            if(src_port == SAMPLE_PORT2)
            {
                dbg_printk("%s[%d]\n", __FUNCTION__, __LINE__);
                tcp_header->source = OS_NTOHS(SAMPLE_PORT1);
                compute_tcp_checksum(ip_header, tcp_header);
                // skb->ip_summed = CHECKSUM_COMPLETE;
            }
        }
    }
    
    return STATUS_DSC_OK;
}

/*****************************************************************************/
/**
*  @brief sample_handler_l3_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT sample_handler_l3_init_driver(T_VOID)
{
    dbg_printk("Start %s\n", __FUNCTION__);
    return 0;
}

/*****************************************************************************/
/**
*  @brief sample_handler_l3_cleanup_driver
*  @param T_VOID
*  @return T_VOID
*/
T_VOID sample_handler_l3_cleanup_driver(T_VOID)
{
    dbg_printk("Clean up %s\n", __FUNCTION__);
}

/** ***********************  END  ********************************************/