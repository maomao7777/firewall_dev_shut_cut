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
#if DSC_DNS_WALLEDGARDEN
#include <dsc_walledgarden_handler.h>
#endif
/** -------------------------------------------------------------------------
                          DEFINITIONS
  -------------------------------------------------------------------------*/
#define dbg_printk(x...)  // printk(x)

#if 1
#define DEV_GET(x) __dev_get_by_name(&init_net,x)
#endif
/** -------------------------------------------------------------------------
                          VARIABLES
  -------------------------------------------------------------------------*/
extern T_UINT32 is_captive_portal;
extern struct captive_portal_group_info group[MAX_CAPTIVE_PORTAL_GROUP];
extern UINT32 g_captive_portal_group;
extern struct mem_info mem[MAX_USERS_NUM];
extern T_UINT32 mem_index;
extern UINT32 lan_ip_address;
#if WLAN_SUPPORT_URL_REDIRECT_VLAN
extern T_UINT32 add_lan_ip[ADDITIONAL_LAN_IP_NUM];
extern T_UINT8  add_ip_idx;
#endif
extern UINT8 dev_mac[ETH_ALEN];
#if DSC_EXTERNAL_CAPTIVE_PORTAL
extern struct external_mem_info external_mem[MAX_EXTERNAL_USERS_NUM];
extern T_UINT32 external_mem_index;
#define EXTERNAL_CAPTIVE_PORTAL_HTML_TEXT "<html"
#define EXTERNAL_CAPTIVE_PORTAL_AUTH_TEXT "auth_key="
#define EXTERNAL_CAPTIVE_PORTAL_HTML_CODE_LEN       (256)
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
T_UINT32 paypal_ip[PASSCODE_PAYPAL_DOMAIN_NUMBER];
T_INT paypal_ip_count =0;
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
T_UINT32 social_login_ip[SOCIAL_LOGIN_DOMAIN_NUMBER+16]; //FB known ip is num of 16
T_INT social_login_ip_count =0;
#endif
#if DSC_DNS_WALLEDGARDEN
extern struct walledgarden walled_garden[MAX_SUPPORT_WALLEDGARDEN_GROUP];
#endif
/* cache data */
UINT8 mac_cache[ETH_ALEN] = {0};        // mac cache
static unsigned long jiffies_cache =0;  // jiffies cache

#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
extern struct user_info user[MAX_USERS_ACCOUNT_NUM];
#endif
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

#if DSC_EXTERNAL_CAPTIVE_PORTAL
/*****************************************************************************/
/**
*  @brief external_captive_portal_handler
*  @param struct sk_buff *skb, unsigned char* auth_key
*  @return T_BOOL
*/
T_BOOL external_captive_portal_catch_key(struct sk_buff* skb, unsigned char *auth_key)
{
    struct iphdr  *ip_header  = (struct iphdr *) (skb->data);
    struct tcphdr *tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
    unsigned char *tcp_payload = (unsigned char *)((unsigned int)tcp_header+tcp_header->doff*4);
    unsigned short int data_len = 0, tcp_hlen = 0, ip_hlen = 0, total_len = 0;
    unsigned int check_range;
    unsigned int code_len = EXTERNAL_CAPTIVE_PORTAL_HTML_CODE_LEN;
    char html_code[EXTERNAL_CAPTIVE_PORTAL_HTML_CODE_LEN+1];
    char *find_html_code, *find_auth_key, *auth_key_start, *auth_key_end;

	total_len = ntohs(ip_header->tot_len);
    tcp_hlen = ((tcp_header->doff)*4);
    ip_hlen = ((ip_header->ihl)*4);
	if(total_len > (tcp_hlen + ip_hlen))
		data_len = total_len - (tcp_hlen + ip_hlen);
    else
        data_len = 0;
    if(0 < data_len)
    {
        if(data_len < code_len)
            check_range = data_len;
        else
            check_range = code_len;

        find_html_code = strstr(tcp_payload, EXTERNAL_CAPTIVE_PORTAL_HTML_TEXT); // start from <html>
        if(NULL != find_html_code)
        {
            memset(html_code, 0, EXTERNAL_CAPTIVE_PORTAL_HTML_CODE_LEN+1);
            memcpy(html_code, find_html_code, check_range);
            find_auth_key = strstr(html_code, EXTERNAL_CAPTIVE_PORTAL_AUTH_TEXT);
  
            if(NULL != find_auth_key)
            {
                auth_key_start = strchr(find_auth_key, '"'); // find first '"'
                if(NULL != auth_key_start)
                {
                    auth_key_start = auth_key_start+1; // skip first '"'
                    auth_key_end = strchr(auth_key_start, '"'); // find second '"'
                    if(NULL != auth_key_end)
                    {
#if !DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL
                        if(AUTH_KEY_LEN >= (auth_key_end - auth_key_start))
#else
                        if(CLOUD_AUTH_KEY_LEN >= (auth_key_end - auth_key_start))
#endif
                        {
                            memcpy(auth_key, auth_key_start, auth_key_end - auth_key_start);
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

/*****************************************************************************/
/**
*  @brief external_captive_portal_l2_catch_key
*  @param struct sk_buff *skb, unsigned char* auth_key
*  @return T_BOOL
*/
T_BOOL external_captive_portal_l2_catch_key(struct sk_buff* skb, unsigned char *auth_key)
{


    unsigned char *data = skb->data;
    struct ethhdr *eth_header = (struct ethhdr *)data;
    struct iphdr  *ip_header  = (struct iphdr *) (skb->data+ETH_HLEN);
	
//    struct iphdr  *ip_header  = (struct iphdr *) (skb->data);
    struct tcphdr *tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
    unsigned char *tcp_payload = (unsigned char *)((unsigned int)tcp_header+tcp_header->doff*4);
    unsigned short int data_len = 0, tcp_hlen = 0, ip_hlen = 0, total_len = 0;
    unsigned int check_range;
    unsigned int code_len = EXTERNAL_CAPTIVE_PORTAL_HTML_CODE_LEN;
    char html_code[EXTERNAL_CAPTIVE_PORTAL_HTML_CODE_LEN+1];
    char *find_html_code, *find_auth_key, *auth_key_start, *auth_key_end;

	total_len = ntohs(ip_header->tot_len);
    tcp_hlen = ((tcp_header->doff)*4);
    ip_hlen = ((ip_header->ihl)*4);
	if(total_len > (tcp_hlen + ip_hlen))
		data_len = total_len - (tcp_hlen + ip_hlen);
    else
        data_len = 0;
    if(0 < data_len)
    {
        if(data_len < code_len)
            check_range = data_len;
        else
            check_range = code_len;

        find_html_code = strstr(tcp_payload, EXTERNAL_CAPTIVE_PORTAL_HTML_TEXT); // start from <html>
        if(NULL != find_html_code)
        {
            memset(html_code, 0, EXTERNAL_CAPTIVE_PORTAL_HTML_CODE_LEN+1);
            memcpy(html_code, find_html_code, check_range);
            find_auth_key = strstr(html_code, EXTERNAL_CAPTIVE_PORTAL_AUTH_TEXT);
  
            if(NULL != find_auth_key)
            {
                auth_key_start = strchr(find_auth_key, '"'); // find first '"'
                if(NULL != auth_key_start)
                {
                    auth_key_start = auth_key_start+1; // skip first '"'
                    auth_key_end = strchr(auth_key_start, '"'); // find second '"'
                    if(NULL != auth_key_end)
                    {
#if !DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL
                        if(AUTH_KEY_LEN >= (auth_key_end - auth_key_start))
#else
                        if(CLOUD_AUTH_KEY_LEN >= (auth_key_end - auth_key_start))
#endif
                        {
                            memcpy(auth_key, auth_key_start, auth_key_end - auth_key_start);
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return 0;
}


/*****************************************************************************/
/**
*  @brief external_captive_portal_guest_find
*  @param unsigned char *mac_addr, int group_id
*  @return T_INT
*/
struct external_mem_info * external_captive_portal_guest_find(unsigned char *mac_addr, int group_id)
{
    int k = 0;
    for(k = 0; k < MAX_EXTERNAL_USERS_NUM; k++)
    {
        if(external_mem[k].group_id == group_id && // memcmp(src_mac, mem[k].mac_addr, ETH_ALEN) == 0 
          (mac_addr[0] == external_mem[k].mac_addr[0]) &&
          (mac_addr[1] == external_mem[k].mac_addr[1]) &&
          (mac_addr[2] == external_mem[k].mac_addr[2]) &&
          (mac_addr[3] == external_mem[k].mac_addr[3]) &&
          (mac_addr[4] == external_mem[k].mac_addr[4]) &&
          (mac_addr[5] == external_mem[k].mac_addr[5]) )
        {
            return &external_mem[k];
        }
    }

	
    return 0;
}
/*****************************************************************************/
/**
*  @brief external_captive_portal_guest_add
*  @param unsigned char *mac_addr, int group_id
*  @return T_INT
*/
struct external_mem_info * external_captive_portal_guest_add(unsigned char *mac_addr, int group_id)
{
    int k = 0;
    int first_replace_idx = -1;
    char mac_null[ETH_ALEN] = {0, 0, 0, 0, 0, 0};

    for(k = 0; k < MAX_EXTERNAL_USERS_NUM; k++) /* add it in database */
    {
        
      if(1 == (mac_null[0] == external_mem[k].mac_addr[0]) &&
              (mac_null[1] == external_mem[k].mac_addr[1]) &&
              (mac_null[2] == external_mem[k].mac_addr[2]) &&
              (mac_null[3] == external_mem[k].mac_addr[3]) &&
              (mac_null[4] == external_mem[k].mac_addr[4]) &&
              (mac_null[5] == external_mem[k].mac_addr[5]) )
        { // if has unused, add in
            memcpy(external_mem[k].mac_addr, mac_addr, ETH_ALEN);
            external_mem[k].group_id = group_id;
            external_mem[k].is_auth = 0;

            return &external_mem[k];
        } 
        if((0 == external_mem[k].is_auth) && (-1 == first_replace_idx))
        { // record index of no-auth mac
            first_replace_idx = k;
        }
    }
    if((k == MAX_EXTERNAL_USERS_NUM) && (-1 != first_replace_idx)) /* if can not add, replace the no-auth mac */
    {
        memcpy(external_mem[first_replace_idx].mac_addr, mac_addr, ETH_ALEN);
        external_mem[first_replace_idx].group_id = group_id;
        external_mem[first_replace_idx].is_auth = 0;

        return &external_mem[first_replace_idx];
    }
    return 0;
}
/*****************************************************************************/
#endif

#if DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL
static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int Base64decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

int Base64decode(char *bufplain, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}
#endif

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count)
{
    register unsigned long sum = 0;
    while (count > 1) {
        sum += * addr++;
        count -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(count > 0) {
        sum += ((*addr)&htons(0xFF00));
    }
    //Fold sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    //one's complement
    sum = ~sum;
    return ((unsigned short)sum);
}
/*****************************************************************************/
/**
*  @brief compute_ip_checksum
*  @param struct iphdr* iphdrp
*  @return T_VOID
*/
T_VOID compute_ip_checksum(struct iphdr* iphdrp)
{
    iphdrp->check = 0;
    iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}

/*****************************************************************************/
/**
*  @brief compute_tcp_checksum
*  @param struct iphdr *pIph
*  @param unsigned short *ipPayload
*  @return T_VOID
*/
T_VOID compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload)
{
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
//       printk("%s[%d]: %x\n", __FUNCTION__, __LINE__, tcphdrp->check);
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %d\n", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
//      printk("%s[%d]: check2 = %x\n", __FUNCTION__, __LINE__, tcphdrp->check);
}

/*****************************************************************************/
/**
*  @brief captive_portal_guest_find
*  @param struct sk_buff *skb
*  @return T_INT
*/
struct mem_info * captive_portal_guest_find(unsigned char *mac_addr, int group_id)
{
    int k;
    for(k = 0; k < MAX_USERS_NUM; k++)
    {
        if(mem[k].group_id == group_id && // memcmp(src_mac, mem[k].mac_addr, ETH_ALEN) == 0 
          (mac_addr[0] == mem[k].mac_addr[0]) &&
          (mac_addr[1] == mem[k].mac_addr[1]) &&
          (mac_addr[2] == mem[k].mac_addr[2]) &&
          (mac_addr[3] == mem[k].mac_addr[3]) &&
          (mac_addr[4] == mem[k].mac_addr[4]) &&
          (mac_addr[5] == mem[k].mac_addr[5]) )
        {
            return &mem[k];
        }
    }

    return 0;

}

#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
/*****************************************************************************/
/**
*  @brief captive_portal_user_info_find
*  @param struct sk_buff *skb
*  @return T_INT
*/
struct user_info * captive_portal_user_info_find(unsigned char *mac_addr)
{
    int k;
    for(k = 0; k < MAX_USERS_ACCOUNT_NUM; k++)
    {
        if((mac_addr[0] == user[k].mac_addr[0]) &&
          (mac_addr[1] == user[k].mac_addr[1]) &&
          (mac_addr[2] == user[k].mac_addr[2]) &&
          (mac_addr[3] == user[k].mac_addr[3]) &&
          (mac_addr[4] == user[k].mac_addr[4]) &&
          (mac_addr[5] == user[k].mac_addr[5]) )
        {
            return &user[k];
        }
    }

    return 0;

}
#endif
/*****************************************************************************/
/**
*  @brief captive_portal_guest_alloc
*  @param struct sk_buff *skb
*  @return T_INT
*/
struct mem_info * captive_portal_guest_alloc(void)
{
    int k, m;
    for(k = 0; k < MAX_USERS_NUM; k++)
    {/* find free entry */
        m = (k+mem_index)%MAX_USERS_NUM;
        if(mem[m].is_auth == 0)
        {
            mem_index = (m+1);
            return &mem[m];
        }
    }
    
    printk("------> %s[%d], error, db full\n", __FUNCTION__, __LINE__);
    return 0;
}
/*****************************************************************************/
#if DSC_DNS_WALLEDGARDEN
static T_INT captive_portal_check_walledgarden_ip(struct captive_portal_group_info *pgroup,struct iphdr *ip_header)
{
    T_UINT32 dst_ip = OS_NTOHL(ip_header->daddr);
	int g;
	for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
	{
		if((pgroup->walledgarden_type)&((UINT64)1 << g))
		{
			if(walled_garden[g].wg_en==1&&check_walledgarden_HostIp(dst_ip, &walled_garden[g]))
			{
				//printk("### %s:%d match ### 0x%08x %s wg_group is [%d]\n",__FUNCTION__,__LINE__,dst_ip,ip_int_to_str(dst_ip),g);
				return 1;
			}
			if(walled_garden[g].wg_en==1&&check_walledgarden_Net(dst_ip, &walled_garden[g]))
			{
				//printk("### %s:%d match ### 0x%08x %s wg_group is [%d]\n",__FUNCTION__,__LINE__,dst_ip,ip_int_to_str(dst_ip),g);
				return 1;	
			}
		}
	}
    return 0;
}
#endif
/*****************************************************************************/
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL || WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
#if WLAN_SUPPORT_URL_REDIRECT_VLAN
static T_BOOL captive_portal_check_local_lan_ip(T_UINT32 ip)
{
    T_UINT8 i;

    for (i=0;i<add_ip_idx;i++)
    {
        if (ip == add_lan_ip[i])
            return TRUE;
    }
    return FALSE;
}
#endif /* WLAN_SUPPORT_URL_REDIRECT_VLAN */
/*****************************************************************************/
/**
*  @brief captive_portal_allow_ip_port_list
*  @param pgroup captive portal group info
*  @param dst_port destination port
*  @param ip_header skb ip header pointer
*  @return T_INT
*/
static T_INT captive_portal_allow_ip_port_list(struct captive_portal_group_info *pgroup,
                                              unsigned short dst_port, struct iphdr *ip_header)
{
    T_UINT32 dst_ip = OS_NTOHL(ip_header->daddr);
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
    int i= 0;
    if(pgroup->paypal_ip_list_enable == 1)
    {
        for(i=0;i<paypal_ip_count;i++)
        {
            if(dst_ip == paypal_ip[i])
            {
                //printk(KERN_ERR "### %s:%d match ### 0x%08x %s \n",__FUNCTION__,__LINE__,paypal_ip[i],ip_int_to_str(paypal_ip[i]));
                return 1;
            }
        }
    }
#endif

    if(dst_port == pgroup->redirect_port && dst_ip == lan_ip_address)
    {
        dbg_printk("------> %s[%d], ok\n", __FUNCTION__, __LINE__);
        return 1;
    }
#if WLAN_SUPPORT_URL_REDIRECT_VLAN
    else if(dst_port == pgroup->redirect_port && captive_portal_check_local_lan_ip(dst_ip))
    {
        dbg_printk("------> %s[%d], ok\n", __FUNCTION__, __LINE__);
        return 1;
    }
#endif
    else if(dst_port == pgroup->external_redirect_port && dst_ip == pgroup->redirect_ip)
    {
        dbg_printk("------> %s[%d], ok\n", __FUNCTION__, __LINE__);
        return 1;
    }
    else if(dst_port == pgroup->external_redirect_port_2 && dst_ip == pgroup->redirect_ip_2)
    {
        dbg_printk("------> %s[%d], ok\n", __FUNCTION__, __LINE__);
        return 1;
    }
    /*
    else if((dst_port== pgroup->input_https_port && dst_ip == lan_ip_address)
		||(dst_port== pgroup->input_http_port && dst_ip == lan_ip_address))
	{
        printk("------> %s[%d], ok\n", __FUNCTION__, __LINE__);
        return 1;
    }
    */
    return 0;
}
#endif
/*****************************************************************************/
/**
*  @brief captive_portal_rx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT captive_portal_rx_handler(struct sk_buff *skb)
{
    // unsigned char *data = skb->data;
    struct ethhdr *eth_header = (struct ethhdr *)(skb->data-ETH_HLEN);
    struct iphdr  *ip_header  = (struct iphdr *) (skb->data);
    struct tcphdr *tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
    struct udphdr *udp_header = (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl);
    
    int i, j, k, m;
    unsigned short int dst_port = 0, src_port = 0;
    unsigned int dst_ip;
    unsigned char src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
    struct net_device *dev;
    struct mem_info *guest_info = 0;

#if DSC_EXTERNAL_CAPTIVE_PORTAL
    int check_pass;
    char ecp_auth_key[AUTH_KEY_LEN];
    struct external_mem_info *external_guest_info = 0;
#endif
#if DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL
    char cloud_ecp_auth_key[CLOUD_AUTH_KEY_LEN];
#endif

#if SHOW_TIME_DIFF
    struct timeval now; 
    suseconds_t diff0, diff; 

    do_gettimeofday(&now); 
    diff0 = now.tv_usec; /* microseconds */ 
#endif
   
    dbg_printk("------> %s[%d], skb->dev->name = %s\n", __FUNCTION__, __LINE__, skb->dev->name);
    if(is_captive_portal)
    {

        /****** AP <- STA ******/
        for(i = 0; i < g_captive_portal_group; i++)
        {
            for(j = 0; j < WLAN_SSID_NUM; j++)
            {
                dev = DEV_GET(group[i].if_names[j]);

                /* AP <- STA */
                if(dev && skb->dev == dev)
                {/* Catpive Portal interface */

                    memcpy(dst_mac, eth_header->h_dest,   ETH_ALEN);
                    memcpy(src_mac, eth_header->h_source, ETH_ALEN);
        
                    guest_info = captive_portal_guest_find(src_mac, i);
#if DSC_EXTERNAL_CAPTIVE_PORTAL
                    external_guest_info = external_captive_portal_guest_find(src_mac, i);
#endif

                    if(guest_info)
                    {
                        if(guest_info->is_auth)
                        {/* STA (auth) */

//                            memcpy(mac_cache, src_mac, ETH_ALEN); /* cache src mac */

#if DSC_EXTERNAL_CAPTIVE_PORTAL
                            check_pass = 0;
                            if(group[i].external_enable)
                            {
                                if(external_guest_info)
                                {
                                    if(external_guest_info->is_auth)
                                    {
                                        check_pass = 1;
                                    }
                                }
                            }
                            else
                            {
                                check_pass = 1;
                            }

                            if(1 == check_pass)
                            {
#endif
                            if((eth_header->h_proto == htons(ETH_P_IP)) && (ip_header->protocol == IPPROTO_TCP)) 
                            {
                                dst_ip = OS_NTOHL(ip_header->daddr);
                            
                                // to redirect IP of AC
                                if(dst_ip == group[i].redirect_ip)
                                {
                                    // always redirect port AC:8902 <- AP:80
                                    dst_port = OS_NTOHS((unsigned short int) tcp_header->dest);
                                    if((80 == dst_port)|| (443 == dst_port))
                                    {/* AC:80 <- AP <- STA (auth), drop it ? */
#if DSC_CAPTIVE_PORTAL_PORT_FORWARDING
                                        /* do port forwarding later */
#else
                                        /* drop */
                                        return STATUS_DSC_DROP_AND_FREE;
#endif
                                    }
                                }
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL || WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
#if WLAN_SUPPORT_URL_REDIRECT_VLAN
								if((dst_ip == lan_ip_address) ||captive_portal_check_local_lan_ip(dst_ip))
								{
									dst_port = OS_NTOHS((unsigned short int) tcp_header->dest);
									if(dst_port!= group[i].redirect_port
										&&dst_port!= group[i].input_http_port
										&&dst_port!= group[i].input_https_port
									)
										return STATUS_DSC_DROP_AND_FREE;
								}
#endif
#endif
							}

                            /* STA is auth */
                            return STATUS_DSC_OK;
#if DSC_EXTERNAL_CAPTIVE_PORTAL
                            }
#endif
                        }
                    }

                    if(eth_header->h_proto == htons(ETH_P_IP))
                    {
                        if(ip_header->protocol == IPPROTO_UDP)
                        {
                            src_port = OS_NTOHS((unsigned short int) udp_header->source);
                            dst_port = OS_NTOHS((unsigned short int) udp_header->dest);
                            
                            if(dst_port == 53) //DNS
                            {
//                                 printk("[%s][%d] --> ******************DNS query\n", __FUNCTION__, __LINE__);
                            }else if(src_port == 68 && dst_port == 67) // DHCP
                            {
//                                 printk("[%s][%d] --> ****************** dhcp discover\n", __FUNCTION__, __LINE__);
                            }else
                            {/* drop packets != UDP(53) */
                                return STATUS_DSC_DROP_AND_FREE;
                            }
                        }
                        else if (ip_header->protocol == IPPROTO_TCP)
                        {
                            src_port = ntohs((unsigned short int) tcp_header->source);
                            dst_port = ntohs((unsigned short int) tcp_header->dest);

                            dbg_printk("%s[%d], src_port = %d, dst_port = %d\n", __FUNCTION__, __LINE__, src_port, dst_port);
#if DSC_EXTERNAL_CAPTIVE_PORTAL
                            if(group[i].external_enable)
                            {
                                if(0 == external_guest_info)
                                {
                                    external_guest_info = external_captive_portal_guest_add(src_mac,i); // add it

                                    if(0 == external_guest_info)
                                    {/* full users */
                                        return STATUS_DSC_DROP_AND_FREE; // means full users and do nothing
                                    }
                                }
								else
								{
                                if(0 == external_guest_info->is_auth)
                                {
                                    dst_ip = OS_NTOHL(ip_header->daddr);
                                    if(dst_ip == group[i].external_redirect_ip) // to external server
                                    {
                                        return STATUS_DSC_OK;
                                    }
                                }
								}
                            }
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
#if DSC_DNS_WALLEDGARDEN
							if(captive_portal_check_walledgarden_ip(&group[i],ip_header))
								 return STATUS_DSC_OK;
#endif
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL || WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
                            if (captive_portal_allow_ip_port_list(&group[i], dst_port, ip_header))
                                return STATUS_DSC_OK;
#endif

                            if(dst_port == 443) // HTTPS
                            {/* AC <- AP:443 <- STA */
                                dst_ip = OS_NTOHL(ip_header->daddr);
                                
                                if(dst_ip == group[i].redirect_ip)
                                {/* AC:8904 <- AP:443 <- STA */
#if DSC_CAPTIVE_PORTAL_PORT_FORWARDING
                                    if(guest_info)
                                    {
                                        memcpy(guest_info->dst_mac, dst_mac, ETH_ALEN);
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                                        for(k = 0; k < MAX_SESSION_NUM; k++)
                                        {
                                            if(src_port == guest_info->https_src_port[k])
                                                break;
                                        }
                                        if(k == MAX_SESSION_NUM)
                                        {
                                            guest_info->https_src_port[guest_info->https_port_index] = src_port;
                                            guest_info->https_dst_ip[guest_info->https_port_index] = dst_ip;
                                            guest_info->https_port_index++;
                                            guest_info->https_port_index = guest_info->https_port_index % MAX_SESSION_NUM;
                                        }
#else
                                        guest_info->dst_ip = dst_ip;
#endif
                                    }else
                                    {
                                        guest_info = captive_portal_guest_alloc();
                                        if(guest_info)
                                        {
                                            memcpy(guest_info->mac_addr, src_mac, ETH_ALEN);
                                            memcpy(guest_info->dst_mac, dst_mac, ETH_ALEN);
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                                            guest_info->https_src_port[0] = src_port;
                                            guest_info->https_dst_ip[0] = dst_ip;
                                            guest_info->https_port_index = 1;
#else
                                            guest_info->dst_ip = dst_ip;
#endif
                                            guest_info->group_id = i;
                                        }else
                                        {
                                            /* could not find free entry */
                                            return STATUS_DSC_DROP_AND_FREE;
                                        }
                                    }

                                    tcp_header->dest = OS_NTOHS(group[i].redirect_https_port);
                                    
                                    compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);

                                    return STATUS_DSC_OK;
#else
                                    return STATUS_DSC_DROP_AND_FREE;
#endif
                                }
                                else
                                {/* AP:8904 <- ???:443 <- STA */
                                    if(guest_info)
                                    {
                                        memcpy(guest_info->dst_mac, dst_mac, ETH_ALEN);
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                                        for(k = 0; k < MAX_SESSION_NUM; k++)
                                        {
                                            if(src_port == guest_info->https_src_port[k])
                                                break;
                                        }
                                        if(k == MAX_SESSION_NUM)
                                        {
                                            guest_info->https_src_port[guest_info->https_port_index] = src_port;
                                            guest_info->https_dst_ip[guest_info->https_port_index] = dst_ip;
                                            guest_info->https_port_index++;
                                            guest_info->https_port_index = guest_info->https_port_index % MAX_SESSION_NUM;
                                        }
#else
                                        guest_info->dst_ip = dst_ip;
#endif
                                    }else
                                    {
                                        guest_info = captive_portal_guest_alloc();
                                        if(guest_info)
                                        {
                                            memcpy(guest_info->mac_addr, src_mac, ETH_ALEN);
                                            memcpy(guest_info->dst_mac, dst_mac, ETH_ALEN);
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                                            guest_info->https_src_port[0] = src_port;
                                            guest_info->https_dst_ip[0] = dst_ip;
                                            guest_info->https_port_index = 1;
#else
                                            guest_info->dst_ip = dst_ip;
#endif
                                            guest_info->group_id = i;
                                        }else
                                        {
                                            /* could not find free entry */
                                            return STATUS_DSC_DROP_AND_FREE;
                                        }
                                    }

                                    /* fix mongoose can't recive packet */
                                    memcpy(eth_header->h_dest, dev_mac, ETH_ALEN);
                                    
                                    /* update dest ip&port to AP:8903 */
                                    ip_header->daddr = lan_ip_address;
                                    tcp_header->dest = OS_NTOHS(group[i].input_https_port);

#if DSC_EXTERNAL_CAPTIVE_PORTAL
                                    if(group[i].external_enable)
                                    {
                                        if(0 == external_guest_info->is_auth)
                                        {
                                            tcp_header->dest = OS_NTOHS(group[i].external_input_https_port);
                                        }
                                    }
#endif
                                    
                                    compute_ip_checksum(ip_header);
                                    compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);

                                    return STATUS_DSC_OK;
                                }
                            }
                            else if(dst_port == 80) // HTTP
                            {/* AC <- AP:80 <- STA */

                                dst_ip = OS_NTOHL(ip_header->daddr);

                                if(dst_ip == group[i].redirect_ip)
                                {/* AC:8902 <- AP:80 <- STA */
#if DSC_CAPTIVE_PORTAL_PORT_FORWARDING
                                    src_port = ntohs((unsigned short int) tcp_header->source);
                                    
                                    if(guest_info)
                                    {
                                        memcpy(guest_info->dst_mac, dst_mac, ETH_ALEN);
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                                        for(k = 0; k < MAX_SESSION_NUM; k++)
                                        {
                                            if(src_port == guest_info->http_src_port[k])
                                                break;
                                        }
                                        if(k == MAX_SESSION_NUM)
                                        {
                                            guest_info->http_src_port[guest_info->http_port_index] = src_port;
                                            guest_info->http_dst_ip[guest_info->http_port_index] = dst_ip;
                                            guest_info->http_port_index++;
                                            guest_info->http_port_index = guest_info->http_port_index % MAX_SESSION_NUM;
                                        }
#else
                                        guest_info->dst_ip = dst_ip;
#endif
                                    }else
                                    {   /* find free entry */
                                        guest_info = captive_portal_guest_alloc();
                                        if(guest_info)
                                        {
                                            memcpy(guest_info->mac_addr, src_mac, ETH_ALEN);
                                            memcpy(guest_info->dst_mac, dst_mac, ETH_ALEN);
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                                            guest_info->http_src_port[0] = src_port;
                                            guest_info->http_dst_ip[0] = dst_ip;
                                            guest_info->http_port_index = 1;
#else
                                            guest_info->dst_ip = dst_ip;
#endif
                                            guest_info->group_id = i;
                                        }else
                                        {
                                            return STATUS_DSC_DROP_AND_FREE;
                                        }
                                    }

                                    /* update AC:8902 <- AP:80 <- STA */
                                    tcp_header->dest = OS_NTOHS(group[i].redirect_http_port);

                                    compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);

                                    return STATUS_DSC_OK;
#else
                                    return STATUS_DSC_DROP_AND_FREE;
#endif

                                }
                                else
                                {/* AP:8901 <- ???:80 <- STA */

                                    if(guest_info)
                                    {
                                        memcpy(guest_info->dst_mac, dst_mac, ETH_ALEN);
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                                        for(k = 0; k < MAX_SESSION_NUM; k++)
                                        {
                                            if(src_port == guest_info->http_src_port[k])
                                                break;
                                        }
                                        if(k == MAX_SESSION_NUM)
                                        {
                                            guest_info->http_src_port[guest_info->http_port_index] = src_port;
                                            guest_info->http_dst_ip[guest_info->http_port_index] = dst_ip;
                                            guest_info->http_port_index++;
                                            guest_info->http_port_index = guest_info->http_port_index % MAX_SESSION_NUM;
                                        }
#else
                                        guest_info->dst_ip = dst_ip;
#endif
                                    }else
                                    {    /* find free entry */
                                        guest_info = captive_portal_guest_alloc();
                                        if(guest_info)
                                        {
                                            memcpy(guest_info->mac_addr, src_mac, ETH_ALEN);
                                            memcpy(guest_info->dst_mac, dst_mac, ETH_ALEN);
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                                            guest_info->http_src_port[0] = src_port;
                                            guest_info->http_dst_ip[0] = dst_ip;
                                            guest_info->http_port_index = 1;
#else
                                            guest_info->dst_ip = dst_ip;
#endif
                                            guest_info->group_id = i;
                                        }else
                                        {
                                            dbg_printk("------> %s[%d], skb->dev->name = %s\n", __FUNCTION__, __LINE__, skb->dev->name);
                                            return STATUS_DSC_DROP_AND_FREE;
                                        }
                                    }

                                    /* fix mongoose can't recive packet */
                                    memcpy(eth_header->h_dest, dev_mac, ETH_ALEN);
                                    
                                    /* update dest ip&port to AP:8901 */
                                    ip_header->daddr = lan_ip_address;
                                    tcp_header->dest = OS_NTOHS(group[i].input_http_port);

#if DSC_EXTERNAL_CAPTIVE_PORTAL
                                    if(group[i].external_enable)
                                    {
                                        if(0 == external_guest_info->is_auth)
                                        {
                                            tcp_header->dest = OS_NTOHS(group[i].external_input_http_port);
                                        }
                                    }
#endif
                                    
                                    compute_ip_checksum(ip_header);
                                    compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);

                                    return STATUS_DSC_OK;
                                }
                            }

#if !DSC_CAPTIVE_PORTAL_PORT_FORWARDING
#if !WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL
                            else if((dst_port == group[i].redirect_http_port)|| (dst_port == group[i].redirect_https_port))
                            {/* AC:8902/8904 <- AP <- STA */
                                dbg_printk("------> %s[%d], drop\n", __FUNCTION__, __LINE__);
                                return STATUS_DSC_OK;
                            }
#endif
                            else if((ip_header->daddr == lan_ip_address) && ((dst_port == group[i].input_http_port)|| (dst_port == group[i].input_https_port)))
                            {/* AP: 8901/8903 <- STA */
                                dbg_printk("------> %s[%d], ok\n", __FUNCTION__, __LINE__);
                                return STATUS_DSC_OK;
                            }

#if DSC_EXTERNAL_CAPTIVE_PORTAL
                            else if((ip_header->daddr == lan_ip_address) && ((dst_port == group[i].external_input_http_port) || (dst_port == group[i].external_input_https_port)))
                            {/* AP: 8905/8906 <- STA */
                                dbg_printk("------> %s[%d], ok\n", __FUNCTION__, __LINE__);
                                return STATUS_DSC_OK;
                            }
#endif
#endif
                            else
                            {/* drop packets != TCP(80/443/8901/8903/8902/8904) */
                                dbg_printk("%s[%d], src_port = %d, dst_port = %d ======> drop\n", __FUNCTION__, __LINE__, src_port, dst_port);
                                return STATUS_DSC_DROP_AND_FREE;
                            }
                        }
                        else
                        {/* drop packets != UDP or TCP */
                            return STATUS_DSC_DROP_AND_FREE;
                        }
                    }
                    else if(eth_header->h_proto == htons(ETH_P_ARP))
                    {
                        return STATUS_DSC_OK;
                    }
                    else if(eth_header->h_proto == htons(ETH_P_PAE))
                    {
                        return STATUS_DSC_OK;
                    }
                    else
                    {
                        return STATUS_DSC_DROP_AND_FREE;
                    }
                    
                    return STATUS_DSC_OK;
                } /* if(dev && skb->dev == dev) */
            } /* for(j = 0; j < WLAN_SSID_NUM; j++) */
        } /* for(i = 0; i < g_captive_portal_group; i++) */
        
#if NMS_SUPPORT_CAPTIVE_PORTAL

#if DSC_CAPTIVE_PORTAL_PORT_FORWARDING

        /* AC -> AP */
        if(i == g_captive_portal_group && j == WLAN_SSID_NUM)
        {/* not in WLAN dev  */
            
            if((eth_header->h_proto == htons(ETH_P_IP)) && (ip_header->protocol == IPPROTO_TCP))
            {
                memcpy(dst_mac, eth_header->h_dest,   ETH_ALEN);
                // memcpy(src_mac, eth_header->h_source, ETH_ALEN);

                // AC:8902 -> AP:80
                src_port = OS_NTOHS((unsigned short int) tcp_header->source);
                
                for(i = 0; i < g_captive_portal_group; i++)
                {
#if 0 // Todo
                    
                    if(!((skb->dev->name[0] == "l") && (skb->dev->name[1] == "o"))) // not AP
                    {

                    // interface between WTP and AC
                    // dev = DEV_GET(group[i].ac_names[j]);

                    // if(dev && skb->dev == dev)
                    // {
                        src_ip = OS_NTOHL(ip_header->saddr);

                         // redirect IP of AC
                           if(src_ip == group[i].redirect_ip)
                           {
#endif
                    /* ??? -> AP -> STA */
                    if(src_port == group[i].redirect_http_port)
                    {
                        guest_info = captive_portal_guest_find(dst_mac, i);
                        if(guest_info)
                        {
                            /* update src ip&port to dest:80 */
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                            for(j = 0; j < MAX_SESSION_NUM; j++)
                            {
                                if(src_port == guest_info->http_src_port[j])
                                {
                                    ip_header->saddr = OS_NTOHL(guest_info->http_dst_ip[j]);
                                    tcp_header->source = OS_NTOHS(80);
                                    break;
                                }
                            }
#else
                            ip_header->saddr = OS_NTOHL(guest_info->dst_ip);                                
                            tcp_header->source = OS_NTOHS(80);
#endif
                            compute_ip_checksum(ip_header);
                            compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);
                            
                            break;
                        }
                    }
                    else if(src_port == group[i].redirect_https_port)
                    {
                        guest_info = captive_portal_guest_find(dst_mac, i);
                        if(guest_info)
                        {
#if DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
                            for(j = 0; j < MAX_SESSION_NUM; j++)
                            {
                                if(src_port == guest_info->https_src_port[j])
                                {
                                    ip_header->saddr = OS_NTOHL(guest_info->https_dst_ip[j]);
                                    tcp_header->source = OS_NTOHS(443);
                                    break;
                                }
                            }
#else
                            ip_header->saddr = OS_NTOHL(guest_info->dst_ip);
                            tcp_header->source = OS_NTOHS(443);
#endif
                                
                            /* update src ip&port to dest:443 */
                            compute_ip_checksum(ip_header);
                            compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);
                        
                            break;
                        }
                    }
                }
            }
        }
#endif
#if DSC_EXTERNAL_CAPTIVE_PORTAL
        /* ECP Server -> AP */
        if(i == g_captive_portal_group && j == WLAN_SSID_NUM)
        {/* not in WLAN dev  */
            if((eth_header->h_proto == htons(ETH_P_IP)) && (ip_header->protocol == IPPROTO_TCP))
            {
                for(i = 0; i < g_captive_portal_group; i++)
                {
                    if(group[i].external_enable)
                    {
                        if(OS_NTOHL(ip_header->saddr) == group[i].external_redirect_ip) // get package from ECP server
                        {
							memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);
							external_guest_info = external_captive_portal_guest_find(dst_mac, i);							
							if(external_guest_info && (external_guest_info->is_auth != 1))
                            {
#if !DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL

                            memset(ecp_auth_key, 0, AUTH_KEY_LEN);
                            if(external_captive_portal_catch_key(skb, ecp_auth_key)) // catch auth key from package
                            {
                                if(0 == memcmp(ecp_auth_key, group[i].external_auth_key, AUTH_KEY_LEN))
                                {
                                          printk("#############%s:%d################# Key Pass !!!\n", __FUNCTION__, __LINE__);
                                          
                                   //         memcpy(dst_mac, eth_header->h_dest, ETH_ALEN);
                                   //        external_guest_info = external_captive_portal_guest_find(dst_mac, i);
                                   //         if(external_guest_info)                               
                            //              {
                                        external_guest_info->is_auth = 1;
                                        break;
                            //                         }
                                    }
                                }
#else

                                memset(cloud_ecp_auth_key, 0, CLOUD_AUTH_KEY_LEN);
                                if(external_captive_portal_catch_key(skb, cloud_ecp_auth_key)) // catch auth key from package
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
#endif
                            }
                        }
                    }
                }
            }
        }
#endif
#endif
    }

#if SHOW_TIME_DIFF
    do_gettimeofday(&now); 
    diff = now.tv_usec - diff0; 
    printk("[%d]: Rx time: %lu\n", __LINE__, diff);
#endif

    return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief captive_portal_handler_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT captive_portal_handler_init_driver(T_VOID)
{
    dbg_printk("Start %s\n", __FUNCTION__);

    memset(mem, 0, sizeof(struct mem_info)*MAX_USERS_NUM);

#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION	
    memset(user, 0, sizeof(struct user_info)*MAX_USERS_ACCOUNT_NUM);
#endif

    return 0;
}

/*****************************************************************************/
/**
*  @brief captive_portal_handler_cleanup_driver
*  @param T_VOID
*  @return T_VOID
*/
T_VOID captive_portal_handler_cleanup_driver(T_VOID)
{
    dbg_printk("Clean up %s\n", __FUNCTION__);
}

/** ***********************  END  ********************************************/
