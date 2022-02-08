/** 
*   @file dns_redirect_l2_handler
*   @brief dns_redirect_l2_handler
*   @author 
*   @version
*   @date 2017/7/20
*   @bug
*   @warning
*/
/** -------------------------------------------------------------------------
                          INCLUDE HEADER FILES
  -------------------------------------------------------------------------*/
#include <linux/ip.h>
#include <linux/udp.h>

#include <dsc_main.h>
#include <dsc_config.h>
#include <dsc_debug.h>

#include <dns_redirect_handler.h>
/** -------------------------------------------------------------------------
                          DEFINITIONS
  -------------------------------------------------------------------------*/
#define dbg_printk(x...)   // printk(x)

/* Forward IP 1 -> IP 2 */
#define SAMPLE_IP1   0x01015fa8//0x3701a8c0  //dns server IP
#define SAMPLE_IP2   0x3301a8c0

#define MAC_HEADER_LEN                  14
#define IP_HEADER_LEN                   20
#define IP_HEADER_PROTOCOL_OFFSET       9
#define IP_HEADER_SRC_IP_OFFSET         12
#define IP_HEADER_DST_IP_OFFSET         16
#define UDP_HEADER_SRC_PORT_OFFSET      (IP_HEADER_LEN+0)
#define UDP_HEADER_DST_PORT_OFFSET      (IP_HEADER_LEN+2)
#define UDP_HEADER_PACKET_LEN_OFFSET    (IP_HEADER_LEN+4)
#define UDP_HEADER_PACKET_CSUM_OFFSET   (IP_HEADER_LEN+6)

extern UINT32 lan_ip_address;
extern UINT32 dst_dns_server_ip;
extern int dns_redirect;
#if CFG_ELX_DSC_DNS_REDIRECT_MULTI_DOMAIN
extern char dns_domain_name[DNS_RED_SUPPORT_DOMAIN_NUM][64+1];
extern char netbios_name[DNS_RED_SUPPORT_DOMAIN_NUM][64+1];
#else
extern char dns_domain_name[32+1];
extern char netbios_name[64+1];
#endif

extern int dns_redirect_name_query_checkin(unsigned char *data, int size, char *dname);

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
*  @brief compute_udp_checksum
*  @param struct iphdr *pIph
*  @return T_INT
*/
int compute_udp_checksum(struct iphdr *pIph)
{
    UINT8 *data = (UINT8 *)pIph;
    UINT16 *pdata;
    UINT32 csum = 0;
    UINT16 csum16 = 0;
    UINT16 len = 0;
    int i;

    /* show udp checksum */
    // pdata   = ((UINT16 *)(data+UDP_HEADER_PACKET_CSUM_OFFSET));

    /* UDP protocol */
    csum = data[IP_HEADER_PROTOCOL_OFFSET];

    /* UDP src IP */
    pdata   = ((UINT16 *)(data+IP_HEADER_SRC_IP_OFFSET));
    csum += OS_NTOHS(*pdata);
    csum += OS_NTOHS(*(++pdata));

    /* UDP dest IP */
    pdata   = ((UINT16 *)(data+IP_HEADER_DST_IP_OFFSET));
    csum += OS_NTOHS(*pdata);
    csum += OS_NTOHS(*(++pdata));

    /* UDP len */
    pdata   = ((UINT16 *)(data+UDP_HEADER_PACKET_LEN_OFFSET));
    len = OS_NTOHS(*pdata);
    csum += OS_NTOHS((*pdata));

    /* clear udp checksum */
    data[UDP_HEADER_PACKET_CSUM_OFFSET] = 0;
    data[UDP_HEADER_PACKET_CSUM_OFFSET+1] = 0;

    pdata = ((UINT16 *)(data+UDP_HEADER_SRC_PORT_OFFSET));
    for(i=0; i<len; i+=2)
    {
        if((len-(len%2)) == i)
        {
            *pdata = *pdata &(OS_NTOHS(0xff00));
        }

        csum += OS_NTOHS(*(pdata++));
    }

    csum16 = (csum>>16) + (csum&0xffff);
    csum16 = ~csum16;

    /* update checksum */
    pdata   = ((UINT16 *)(data+UDP_HEADER_PACKET_CSUM_OFFSET));
//20150417 wendy: MTK platform is little endian, we need to change "csum16" to host byte order.
    *pdata = OS_NTOHS(csum16);

    return 0;

}

/*****************************************************************************/
/**
*  @brief dns_redirect_l2_rx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT dns_redirect_l2_rx_handler(struct sk_buff *skb)
{
    return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief dns_redirect_l2_tx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT dns_redirect_l2_tx_handler(struct sk_buff *skb)
{
    unsigned char *data = skb->data;
    struct ethhdr *eth_header = (struct ethhdr *)data;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    unsigned short src_port=0, dst_port=0;
    unsigned char *pdns;
    int ret;
#if CFG_ELX_DSC_DNS_REDIRECT_MULTI_DOMAIN
	int index;
#endif

    if(dns_redirect==0)
        return STATUS_DSC_OK;
    /*dbg_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    dbg_printk("%s[%d], %s\n", __FUNCTION__, __LINE__, skb->dev->name);
    dbg_printk("%s[%d], %x\n", __FUNCTION__, __LINE__, eth_header->h_proto);//
    dbg_printk("%s[%d], %x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__, eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2], eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
    dbg_printk("%s[%d], %x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__, eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2], eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);
    */

    if(eth_header->h_proto == htons(ETH_P_IP))
    {
        ip_header = (struct iphdr*)(data+ETH_HLEN);

        // dbg_printk("%s[%d], ip_header->daddr = %x\n", __FUNCTION__, __LINE__, ip_header->daddr);
        // dbg_printk("%s[%d], ip_header->saddr = %x\n", __FUNCTION__, __LINE__, ip_header->saddr);
        // dbg_printk("%s[%d], ip_header->protocol = %x\n", __FUNCTION__, __LINE__, ip_header->protocol);
        if(ip_header->protocol == IPPROTO_UDP)
        {
            udp_header= (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl);
            src_port = htons((unsigned short int) udp_header->source);
            dst_port = htons((unsigned short int) udp_header->dest);
            // dbg_printk("%s[%d], src_port= %d, dst_port=%d\n", __FUNCTION__, __LINE__, src_port, dst_port);

            pdns = (unsigned char *)udp_header;
            pdns += sizeof(struct udphdr);

                
            if(src_port == DNS_PORT)
            {
                if(ip_header->saddr==lan_ip_address)
                {
                    ip_header->saddr = dst_dns_server_ip;
                    compute_ip_checksum(ip_header);
                    compute_udp_checksum(ip_header);
                    skb->ip_summed = CHECKSUM_COMPLETE;
                }
            }else if((src_port==NETBIOS_PORT)&&(dst_port == NETBIOS_PORT))
            {
                /* check redirect packet payload */
#if CFG_ELX_DSC_DNS_REDIRECT_MULTI_DOMAIN
				for(index=0;index<DNS_RED_SUPPORT_DOMAIN_NUM;index++){
					ret = dns_redirect_name_query_checkin(pdns, htons(udp_header->len), netbios_name[index]);
					if(ret==MATCH_DOMAIN_NAME)
						break;
				}
#else
				ret = dns_redirect_name_query_checkin(pdns, htons(udp_header->len), netbios_name);
#endif
                if(MATCH_DOMAIN_NAME == ret)
                {
                    /* do not pass to LAN */
                    if(strncmp(skb->dev->name, "eth", 3) == 0)
                    {
                        dbg_printk("%s[%d], %s\n", __FUNCTION__, __LINE__, skb->dev->name);
                        return STATUS_DSC_DROP;
                    }
                }
            }
        }
    }

    return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief dns_redirect_l2_handler_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT dns_redirect_l2_handler_init_driver(T_VOID)
{
    dbg_printk("Start %s\n", __FUNCTION__);
    return 0;
}

/*****************************************************************************/
/**
*  @brief dns_redirect_l2_handler_cleanup_driver
*  @param T_VOID
*  @return T_VOID
*/
T_VOID dns_redirect_l2_handler_cleanup_driver(T_VOID)
{
    dbg_printk("Clean up %s\n", __FUNCTION__);
}

/** ***********************  END  ********************************************/
