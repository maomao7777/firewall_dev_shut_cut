/** 
*   @file dns_redirect_l3_handler
*   @brief dns_redirect_l3_handler
*   @author JeffYang
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
#include <linux/string.h>

#include <dsc_main.h>
#include <dsc_config.h>
#include <dsc_debug.h>

#include <dns_redirect_handler.h>
/** -------------------------------------------------------------------------
                          DEFINITIONS
  -------------------------------------------------------------------------*/
#define dbg_printk(x...)   // printk(x)

/** -------------------------------------------------------------------------
                          VARIABLES
  -------------------------------------------------------------------------*/
extern int compute_udp_checksum(struct iphdr *pIph);
extern T_VOID compute_ip_checksum(struct iphdr* iphdrp);
// extern T_VOID compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload);

extern UINT32 lan_ip_address;
extern UINT8 lan_mac_address[ETH_ALEN];
extern int dns_redirect;
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
extern char dns_domain_name[DNS_RED_SUPPORT_DOMAIN_NUM][64+1];
#else
extern char dns_domain_name[32+1];
#endif
UINT32 dst_dns_server_ip;
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
*  @brief dns_redirect_readname
*  @param  
*  @return STRING
*/
u_char* dns_redirect_readname(unsigned char* reader,unsigned char* buffer,int* count, unsigned char *rname)
{
    // static unsigned char name[256];
    unsigned int p=0,jumped=0,offset;
    int i , j;

    *count = 1;

    rname[0]='\0';

    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            rname[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    rname[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)rname);i++) 
    {
        p=rname[i];
        for(j=0;j<(int)p;j++) 
        {
            rname[i]=rname[i+1];
            i=i+1;
        }
        rname[i]='.';
    }
    rname[i-1]='\0'; //remove the last dot
    return rname;
}

/*****************************************************************************/
/**
*  @brief dns_redirect_name_query_checkin
*  @param struct 
*  @return INT
*/
int dns_redirect_name_query_checkin(unsigned char *data, int size, char *dname)
{
    // memcpy(skb->data, dns_response, sizeof(dns_response));

    // unsigned char buf[65537],*qname,*reader;
    static unsigned char buf[2048], *qname,*reader;
    unsigned char rname[256];
    int i , n , stop; // , s;
    int q_count = 0;

//     struct sockaddr_in a;

//     static struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    // struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    // struct QUESTION *qinfo = NULL;
    // char *name;
    

//     dbg_printk("%s[%d], size = %d\n", __FUNCTION__, __LINE__, size);

    if(size > 1600)
    {
        dbg_printk("%s[%d], wrong packet size = %d > 1600\n", __FUNCTION__, __LINE__, size);
        return MATCH_DOMAIN_ERROR;
    }

    // memcpy(buf, (skb->data+MAC_HEADER_LEN+IP_HEADER_LEN+UDP_HEADER_LEN), 256);
    memcpy(buf, data, size);

    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;
    
    //point to the query portion
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

//     dbg_printk("\nThe response contains : ");
//     dbg_printk("\n %d Questions.",ntohs(dns->q_count));
//     dbg_printk("\n %d Answers.",ntohs(dns->ans_count));
//     dbg_printk("\n %d Authoritative Servers.",ntohs(dns->auth_count));
//     dbg_printk("\n %d Additional records.\n\n",ntohs(dns->add_count));

    q_count = ntohs(dns->q_count);

    /* only support 1 Query */
    if(1 != q_count)
        return MATCH_DOMAIN_ERROR;

    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER)];

    //Start reading answers
    stop=0;

    //reading 1 query
    for(i=0; i<q_count; i++)
    {
        dns_redirect_readname(reader, buf, &stop, rname);

        n = strlen(dname);
        if(n && (strncasecmp(rname, dname, n) == 0))
        {
            // printk("%s[%d], rname = %s, dname = %s\n", __FUNCTION__, __LINE__, rname, dname);
            return MATCH_DOMAIN_NAME;
        }
    }

    return MATCH_DOMAIN_ERROR;
}

/*****************************************************************************/
/**
*  @brief dns_redirect_l3_rx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT dns_redirect_l3_rx_handler(struct sk_buff *skb)
{
    struct iphdr *ip_header;
//     struct tcphdr *tcp_header;
    struct udphdr *udp_header;
//     unsigned char src_mac[ETH_ALEN];
    UINT16 dst_port = 0, src_port = 0;
    unsigned char *pdns;
    int ret=-1;
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
	int index;
#endif
    if(dns_redirect==0)
        return STATUS_DSC_OK;
//     dbg_printk("-------------------------\n");
//     dbg_printk("%s[%d], %s\n", __FUNCTION__, __LINE__, skb->dev->name);
//     dbg_printk("%s[%d], %x\n", __FUNCTION__, __LINE__, skb->protocol);

    // skb_dump0(__FUNCTION__, skb);

    if(skb->protocol == htons(ETH_P_IP))
    {
        ip_header = (struct iphdr *)skb_network_header(skb);
//         dbg_printk("%s[%d], ip_header->daddr = %x\n", __FUNCTION__, __LINE__, ip_header->daddr);
//         dbg_printk("%s[%d], ip_header->saddr = %x\n", __FUNCTION__, __LINE__, ip_header->saddr);
//         dbg_printk("%s[%d], ip_header->protocol = %x\n", __FUNCTION__, __LINE__, ip_header->protocol);

        if(ip_header->protocol == IPPROTO_UDP)
        {
            udp_header= (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl);

            src_port = htons((unsigned short int) udp_header->source);
            dst_port = htons((unsigned short int) udp_header->dest);

            if((dst_port==DNS_PORT)||(dst_port==LLMNR_PORT))
            {
                pdns = (unsigned char *)udp_header;
                pdns += sizeof(struct udphdr);

                /* check redirect packet payload */
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
				for(index=0;index<DNS_RED_SUPPORT_DOMAIN_NUM;index++){
					ret=dns_redirect_name_query_checkin(pdns, htons(udp_header->len), dns_domain_name[index]);
					if (ret==MATCH_DOMAIN_NAME)
						break;
				}
#else
                ret = dns_redirect_name_query_checkin(pdns, htons(udp_header->len), dns_domain_name);
#endif

                if( MATCH_DOMAIN_NAME == ret )
                {
                    if(dst_port==DNS_PORT)
                    {
                        memcpy(skb->data-ETH_HLEN, lan_mac_address, ETH_ALEN); //TODO ethernet header
                        /* store dns server address */
                        if(ip_header->daddr != lan_ip_address)
                        {
                            dst_dns_server_ip = ip_header->daddr;
                            ip_header->daddr = lan_ip_address;
                            compute_ip_checksum(ip_header);
                            compute_udp_checksum(ip_header);
                        }
                     }else
                     {
                         // todo
                    }
                }
            }
        }
    }

    return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief dns_redirect_l3_tx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT dns_redirect_l3_tx_handler(struct sk_buff *skb)
{

    return STATUS_DSC_OK;
}

/*****************************************************************************/
/**
*  @brief dns_redirect_l3_handler_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT dns_redirect_l3_handler_init_driver(T_VOID)
{
    dbg_printk("Start %s\n", __FUNCTION__);
    return 0;
}

/*****************************************************************************/
/**
*  @brief dns_redirect_l3_handler_cleanup_driver
*  @param T_VOID
*  @return T_VOID
*/
T_VOID dns_redirect_l3_handler_cleanup_driver(T_VOID)
{
    dbg_printk("Clean up %s\n", __FUNCTION__);
}

/** ***********************  END  ********************************************/
