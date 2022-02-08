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
#define dbg_printk(x...)  // printk(x)

#if 1
#define DEV_GET(x) __dev_get_by_name(&init_net,x)
#endif

#define SHOW_TIME_DIFF                             0

/** -------------------------------------------------------------------------
                          VARIABLES
  -------------------------------------------------------------------------*/
extern T_UINT32 mem_index;
extern UINT8 dev_mac[ETH_ALEN];

extern UINT32 lan_ip_address;
extern T_UINT32 is_captive_portal;
extern struct captive_portal_group_info group[MAX_CAPTIVE_PORTAL_GROUP];
extern UINT32 g_captive_portal_group;
extern struct mem_info mem[MAX_USERS_NUM];
#if CAPTIVE_PORTAL_TRAFFIC_LIMITATION
extern struct user_info user[MAX_USERS_ACCOUNT_NUM];
struct user_info * captive_portal_user_info_find(unsigned char *mac_addr);
struct mem_info * captive_portal_guest_find(unsigned char *mac_addr, int group_id);
#endif

struct external_mem_info * external_captive_portal_guest_find(unsigned char *mac_addr, int group_id);
int Base64decode(char *bufplain, const char *bufcoded);
T_BOOL external_captive_portal_l2_catch_key(struct sk_buff* skb, unsigned char *auth_key);

/** -------------------------------------------------------------------------
                          FUNCTIONS
  -------------------------------------------------------------------------*/
#if 0
void skb_dump0(char *name,struct sk_buff* sk) {
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
/*****************************************************************************/
/**
*  @brief captive_portal_l2_rx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT captive_portal_l2_rx_handler(struct sk_buff *skb)
{

#if CAPTIVE_PORTAL_TRAFFIC_LIMITATION
unsigned char *data = skb->data;
struct ethhdr *eth_header = (struct ethhdr *)data;
struct iphdr  *ip_header  = (struct iphdr *) (skb->data+ETH_HLEN);
struct tcphdr *tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
struct udphdr *udp_header = (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl);

int i, j, k;
unsigned short int dst_port = 0, src_port = 0;
unsigned int dst_ip;
unsigned char src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
struct net_device *dev;

unsigned char mac_null[6] = {0, 0, 0, 0, 0, 0};
struct mem_info *guest_info = 0;
struct user_info *user_info = 0;

unsigned short int	data_len = 0, tcp_hlen = 0, ip_hlen = 0, udp_hlen = 0, total_len = 0;


if(is_captive_portal)
{
	for(i = 0; i < g_captive_portal_group; i++)
	{
		for(j = 0; j < WLAN_SSID_NUM; j++)
		{
			dev = DEV_GET(group[i].if_names[j]);
			if(dev && skb->dev == dev)
			{					
				memcpy(dst_mac, eth_header->h_dest,   ETH_ALEN);
				memcpy(src_mac, eth_header->h_source, ETH_ALEN);
									
				guest_info = captive_portal_guest_find(src_mac, i);
				user_info = captive_portal_user_info_find(src_mac);

				if(guest_info)
				{
					if(guest_info->is_auth)
					{/* STA (auth) */

						if(user_info)
						{
							if(user_info->type == 1)
							{
#if 1							
								data_len = 0;
								total_len = ntohs(ip_header->tot_len);								
									tcp_hlen = ((tcp_header->doff)*4);									
									ip_hlen = ((ip_header->ihl)*4);
									udp_hlen = 8;
								
								if (ip_header->protocol == IPPROTO_TCP)
								{
									if(total_len > (tcp_hlen + ip_hlen))
									{
										data_len = total_len - (tcp_hlen + ip_hlen);
									}
									else
									{
										data_len = 0;	
								}
								}
								else if (ip_header->protocol == IPPROTO_UDP)
								{
									if(total_len > (udp_hlen + ip_hlen))
									{
										data_len = total_len - (udp_hlen + ip_hlen);
									}
									else
									{
										data_len = 0;
									}
								}
								else
								{
									data_len = total_len;
								}
#endif								
									
								//check traffic quota									
//								if(ip_header->tot_len >= user_info->traffic_quota)
								if(data_len >= user_info->traffic_quota)
								{
									guest_info->is_auth = 0;
									user_info->traffic_quota = 0;
									
									memcpy(user_info->mac_addr, mac_null, sizeof(mac_null));
									
									printk("#############%s:%d#################Traffic Limitation is exceed\n", __FUNCTION__, __LINE__);
									return STATUS_DSC_DROP_AND_FREE;
								}
								else
								{
//									if (ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_UDP)
//									user_info->traffic_quota = (user_info->traffic_quota) - ip_header->tot_len;
									user_info->traffic_quota = (user_info->traffic_quota) - data_len;
								}

							}
						}

//						return STATUS_DSC_OK;
					}
				}
				
				return STATUS_DSC_OK;
			}
			
		}


	}
}
#endif

#if 1
// move to L3 Rx callback, we could not drop packets in L2 Rx callbackz
#endif

    return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief captive_portal_l2_tx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT captive_portal_l2_tx_handler(struct sk_buff *skb)
{
    int i, j;
#if CAPTIVE_PORTAL_MULTIPLE_SESSION
    int k;
#endif
    unsigned char *data = skb->data;
    struct ethhdr *eth_header = (struct ethhdr *)data;
    struct iphdr  *ip_header  = (struct iphdr *) (skb->data+ETH_HLEN);
    struct tcphdr *tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
    struct udphdr *udp_header = (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl);
    
    unsigned char dst_mac[ETH_ALEN], empty[ETH_ALEN] = {0};
    UINT16 dst_port = 0, src_port = 0;
    UINT32 dst_ip, src_ip;

#if CAPTIVE_PORTAL_TRAFFIC_LIMITATION
    unsigned char src_mac[ETH_ALEN];
	unsigned char mac_null[6] = {0, 0, 0, 0, 0, 0};

    struct net_device *dev;
	struct mem_info *guest_info = 0;
	struct user_info *user_info = 0;
	
	unsigned short int	data_len = 0, tcp_hlen = 0, ip_hlen = 0, udp_hlen = 0,total_len = 0;
#endif	

#if EXTERNAL_CAPTIVE_PORTAL
    int check_pass;
    char ecp_auth_key[AUTH_KEY_LEN];
    struct external_mem_info *external_guest_info = 0;
#endif
#if CLOUD_EXTERNAL_CAPTIVE_PORTAL
    char cloud_ecp_auth_key[CLOUD_AUTH_KEY_LEN];
#endif

    dbg_printk("------> %s[%d], skb->dev->name = %s\n", __FUNCTION__, __LINE__, skb->dev->name);    
    
    if(is_captive_portal)
    {

#if 0 // Todo
        // AP ("lo") -> STA
        if((skb->dev->name[0] == "l") && (skb->dev->name[1] == "o")) // AP ("lo")
        {

#endif

#if CAPTIVE_PORTAL_TRAFFIC_LIMITATION
		for(i = 0; i < g_captive_portal_group; i++)
		{
			for(j = 0; j < WLAN_SSID_NUM; j++)
			{
				dev = DEV_GET(group[i].if_names[j]);
				if(dev && skb->dev == dev)
				{					
					memcpy(dst_mac, eth_header->h_dest,   ETH_ALEN);
					memcpy(src_mac, eth_header->h_source, ETH_ALEN);
										
					guest_info = captive_portal_guest_find(dst_mac, i);
					user_info = captive_portal_user_info_find(dst_mac);

					if(guest_info)
					{
						if(guest_info->is_auth)
						{/* STA (auth) */

							if(user_info)
							{
								if(user_info->type == 1)
								{
#if 1							
									data_len = 0;
									total_len = ntohs(ip_header->tot_len);
										tcp_hlen = ((tcp_header->doff)*4);									
										ip_hlen = ((ip_header->ihl)*4);
										udp_hlen = 8;
										
									if (ip_header->protocol == IPPROTO_TCP)
									{		
										if(total_len> (tcp_hlen + ip_hlen))
										{
											data_len = total_len - (tcp_hlen + ip_hlen);
										}
										else
										{
											data_len = 0;	
									}
									}
									else if (ip_header->protocol == IPPROTO_UDP)
									{										
										if(total_len > (udp_hlen + ip_hlen))
										{
											data_len = total_len - (udp_hlen + ip_hlen);
										}
										else
										{
											data_len = 0;	
									}
									}
									else
									{
										data_len = total_len;
									}
#endif								
									//check traffic quota
//									if(ip_header->tot_len >= user_info->traffic_quota)
									if(data_len >= user_info->traffic_quota)
									{
										guest_info->is_auth = 0;
										user_info->traffic_quota = 0;
										
										memcpy(user_info->mac_addr, mac_null, sizeof(mac_null));
										printk("#############%s:%d#################Traffic Limitation is exceed\n", __FUNCTION__, __LINE__);
										return STATUS_DSC_DROP_AND_FREE;
									}
									else
									{
//										if (ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_UDP)
//										user_info->traffic_quota = (user_info->traffic_quota) - ip_header->tot_len;
										user_info->traffic_quota = (user_info->traffic_quota) - data_len;
									}
									
								}
							}

//							return STATUS_DSC_OK;
						}
					}
					
					return STATUS_DSC_OK;
				}
				
			}


		}
#endif		

        if((eth_header->h_proto == htons(ETH_P_IP)) && (ip_header->protocol == IPPROTO_TCP))
        {
            src_port = htons((unsigned short int) tcp_header->source);
            dst_port = htons((unsigned short int) tcp_header->dest);
            
            dbg_printk("%s[%d], src_port = %d, dst_port = %d\n", __FUNCTION__, __LINE__, src_port, dst_port);

            for(i = 0; i < g_captive_portal_group; i++)
            {

#if CLOUD_EXTERNAL_CAPTIVE_PORTAL
#if CFG_ELX_NMS_SUPPORT_CLOUD_AGENT_IN_AP_ROUTER
				if(group[i].external_enable && group[i].external_is_router)
				{
					if(OS_NTOHL(ip_header->saddr) == group[i].external_redirect_ip) // get package from ECP server
					{
					
						memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);
#if 0							
						printk("##############################%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n"
						, dst_mac[0] & 0xff
						, dst_mac[1] & 0xff
						, dst_mac[2] & 0xff
						, dst_mac[3] & 0xff
						, dst_mac[4] & 0xff
						, dst_mac[5] & 0xff);
#endif
						external_guest_info = external_captive_portal_guest_find(dst_mac, i);							
						if(external_guest_info && (external_guest_info->is_auth != 1))
						{
							memset(cloud_ecp_auth_key, 0, CLOUD_AUTH_KEY_LEN);
							if(external_captive_portal_l2_catch_key(skb, cloud_ecp_auth_key)) // catch auth key from package
							{
								char dec64[50]={0};
								memset(dec64, 0, 50);
								Base64decode(dec64,cloud_ecp_auth_key);

								if(0 == memcmp(dec64, group[i].external_auth_key, 16)) //compare 16 bytes
								{
									printk("#############%s:%d################# Key Pass !!!\n", __FUNCTION__, __LINE__);

									guest_info = captive_portal_guest_find(dst_mac, i);
									if(guest_info && guest_info->is_auth != 1)
									{
										guest_info->is_auth = 1;
									}
									external_guest_info->is_auth = 1;
									break;
								}
							}
						}
					}
				}
#endif				
#endif
                /* AP:8901/8903 -> STA */
                if(src_port == group[i].input_http_port || src_port == group[i].input_https_port)
                {dbg_printk("------> %s[%d], skb->dev->name = %s\n", __FUNCTION__, __LINE__, skb->dev->name);  
                    src_ip = ip_header->saddr;
                    memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);

                    if(lan_ip_address == src_ip)
                    {
                        for(j = 0; j < MAX_USERS_NUM; j++)
                        {
                            if(memcmp(empty, dst_mac, ETH_ALEN) != 0 && mem[j].group_id == i && memcmp(mem[j].mac_addr, dst_mac, ETH_ALEN) == 0)
                            {
#if CAPTIVE_PORTAL_MULTIPLE_SESSION
                                if(src_port == group[i].input_http_port)
                                {
                                    for(k = 0; k < MAX_SESSION_NUM; k++)
                                    {
                                        if(dst_port == mem[j].http_src_port[k])
                                        {
                                            ip_header->saddr = OS_NTOHL(mem[j].http_dst_ip[k]);
                                            tcp_header->source = OS_NTOHS(80);
                                            break;
                                        }
                                    }
                                }
                                else if(src_port == group[i].input_https_port)
                                {
                                    for(k = 0; k < MAX_SESSION_NUM; k++)
                                    {
                                        if(dst_port == mem[j].https_src_port[k])
                                        {
                                            ip_header->saddr = OS_NTOHL(mem[j].https_dst_ip[k]);
                                            tcp_header->source = OS_NTOHS(443);
                                            break;
                                        }
                                    }
                                }
#else
                                ip_header->saddr = OS_NTOHL(mem[j].dst_ip);
                                tcp_header->source = (src_port == group[i].input_http_port) ? OS_NTOHS(80) : OS_NTOHS(443);
#endif

                                compute_ip_checksum(ip_header);
                                compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);
                                memcpy(eth_header->h_source, mem[j].dst_mac, ETH_ALEN);
                            
                                /* fix checksum re-calculate*/
                                skb->ip_summed = CHECKSUM_COMPLETE;
                                break;
                            }
                        }
                        if(j < MAX_USERS_NUM)
                            break;
                    }
                }
#if EXTERNAL_CAPTIVE_PORTAL
                else if(src_port == group[i].external_input_http_port || src_port == group[i].external_input_https_port)
                {/* AP:8905/8906 -> STA */
                    src_ip = ip_header->saddr;
                    memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);

                    if(lan_ip_address == src_ip)
                    {
                        for(j = 0; j < MAX_USERS_NUM; j++)
                        {
                            if(memcmp(empty, dst_mac, ETH_ALEN) != 0 && mem[j].group_id == i && memcmp(mem[j].mac_addr, dst_mac, ETH_ALEN) == 0)
                            {
#if CAPTIVE_PORTAL_MULTIPLE_SESSION
                                if(src_port == group[i].external_input_http_port)
                                {
                                    for(k = 0; k < MAX_SESSION_NUM; k++)
                                    {
                                        if(dst_port == mem[j].http_src_port[k])
                                        {
                                            ip_header->saddr = OS_NTOHL(mem[j].http_dst_ip[k]);
                                            tcp_header->source = OS_NTOHS(80);
                                            break;
                                        }
                                    }
                                }
                                else if(src_port == group[i].external_input_https_port)
                                {
                                    for(k = 0; k < MAX_SESSION_NUM; k++)
                                    {
                                        if(dst_port == mem[j].https_src_port[k])
                                        {
                                            ip_header->saddr = OS_NTOHL(mem[j].https_dst_ip[k]);
                                            tcp_header->source = OS_NTOHS(443);
                                            break;
                                        }
                                    }
                                }
#else
                                ip_header->saddr = OS_NTOHL(mem[j].dst_ip);
                                tcp_header->source = (src_port == group[i].external_input_http_port) ? OS_NTOHS(80) : OS_NTOHS(443);
#endif
                                compute_ip_checksum(ip_header);
                                compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);
                                memcpy(eth_header->h_source, mem[j].dst_mac, ETH_ALEN);

                                /* fix checksum re-calculate*/
                                skb->ip_summed = CHECKSUM_COMPLETE;
                                break;
                            }
                        }
                        if(j < MAX_USERS_NUM)
                            break;
                    }
                }
#endif
#if 0
                else if(dst_port == group[i].redirect_http_port || dst_port == group[i].redirect_https_port)
                {/* AC:8902 <- AP */

                    dst_ip = ip_header->daddr;
                    for(j = 0; j < MAX_USERS_NUM; j++)
                    {
                        if(mem[j].group_id == i && mem[j].dst_ip == dst_ip)
                        {
                            mac0 = eth_header->h_dest;
                            mac1 = dst_mac;
                            mac2 = group[i].redirect_mac;
                            memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);
                            memcpy(mem[j].dst_mac, dst_mac, ETH_ALEN);
                            memcpy(eth_header->h_dest, group[i].redirect_mac, ETH_ALEN);

                            break;
                        }
                    }
                    if(j < MAX_USERS_NUM)
                        break;
                }
#endif
#if CFG_ELX_NMS_SUPPORT_AC_WITH_SELF_WTP
#if CAPTIVE_PORTAL_PORT_FORWARDING
                else if((src_port == group[i].redirect_http_port || src_port == group[i].redirect_https_port))
                {/* AP:(8902/8904->80/443) -> STA */
                    src_ip = ip_header->saddr;
                    memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);
                    
                    if(lan_ip_address == src_ip) //for AC self WTP
                    {
                        for(j = 0; j < MAX_USERS_NUM; j++)
                        {
                            if(memcmp(empty, dst_mac, ETH_ALEN) != 0 && mem[j].group_id == i && memcmp(mem[j].mac_addr, dst_mac, ETH_ALEN) == 0)
                            {
#if CAPTIVE_PORTAL_MULTIPLE_SESSION
                                if(src_port == group[i].redirect_http_port)
                                {
                                    for(k = 0; k < MAX_SESSION_NUM; k++)
                                    {
                                        if(dst_port == mem[j].http_src_port[k])
                                        {
                                            ip_header->saddr = OS_NTOHL(mem[j].http_dst_ip[k]);
                                            tcp_header->source = OS_NTOHS(80);
                                            break;
                                        }
                                    }
                                }
                                else if(src_port == group[i].redirect_https_port)
                                {
                                    for(k = 0; k < MAX_SESSION_NUM; k++)
                                    {
                                        if(dst_port == mem[j].https_src_port[k])
                                        {
                                            ip_header->saddr = OS_NTOHL(mem[j].https_dst_ip[k]);
                                            tcp_header->source = OS_NTOHS(443);
                                            break;
                                        }
                                    }
                                }
#else
                                ip_header->saddr = OS_NTOHL(mem[j].dst_ip);
                                tcp_header->source = (src_port == group[i].redirect_http_port) ? OS_NTOHS(80) : OS_NTOHS(443);
#endif
                                
                                compute_ip_checksum(ip_header);
                                compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);

                                memcpy(eth_header->h_source, mem[j].dst_mac, ETH_ALEN);
                                
                                /* fix checksum re-calculate*/
                                skb->ip_summed = CHECKSUM_COMPLETE;
                                break;
                            }
                        }
                        if(j < MAX_USERS_NUM)
                            break;
                    }
                }
#endif
#endif
                else
                {
                    // dbg_printk("%s[%d]\n", __FUNCTION__, __LINE__);
                }
            }
        }
    }

    return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief captive_portal_handler_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT captive_portal_l2_handler_init_driver(T_VOID)
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
T_VOID captive_portal_l2_handler_cleanup_driver(T_VOID)
{
    dbg_printk("Clean up %s\n", __FUNCTION__);
}

/** ***********************  END  ********************************************/
