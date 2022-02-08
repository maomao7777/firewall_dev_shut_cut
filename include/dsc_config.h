#ifndef _DSC_CONFIG_H
#define _DSC_CONFIG_H

#include <linux/netdevice.h>             /* for struct net_device */
#include "dsc_main.h"

#define MAX_WAN_IF_NUM  (4)
#define MAX_LAN_IF_NUM  (4+CFG_ELX_RADIO_24G_SSID_NUMBERS+CFG_ELX_RADIO_5G_SSID_NUMBERS)
#define MAX_WLAN_IF_NUM  (4)
#define MAX_IPTV_IF_NUM  (5)
#define MAX_GUEST_NETWORK_IF_NUM  (4)
#define MACADDR_LEN     (6)
#define MAX_IFNAME_LEN  32
#define MAX_MAC_PASS_TABLE  10
#define MAX_VLAN_PASS_TABLE 10
#define MAX_PORT_NUM    8   /* 4*LAN 4*Wirelese */
#define MAX_VLAN_ID     4096
#define MAX_CHECK_IP 3
#define MAX_SPAM_MAIL_LIST_NUM	CFG_ELX_WLAN_GUEST_NETWORK_USER_ACCOUNT_NUM
#define MAX_PACKET_SIZE 30*1024*1024
#define MAX_RESET_TIME  60*60*1024
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_VLAN
#define ADDITIONAL_LAN_IP_NUM   15+1
#endif

#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
#define PASSCODE_PAYPAL_DOMAIN_NUMBER       28
#endif
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || CFG_ELX_NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
#define SOCIAL_LOGIN_DOMAIN_NUMBER          20
#endif
#if CFG_ELX_DSC_RECORD_CLIENT_REQ
#define NUM_RECORD_CLINENT_INFO    128
#define PROC_CLIENT_REQ             "client_req"
#endif
#if CFG_ELX_DSC_DNS_WALLEDGARDEN
#define PROC_DNS_WALLEDGARDEN             "dsc_wallgarden"
#endif
#if CFG_ELX_DSC_DNS_REDIRECT_MULTI_DOMAIN
#define DNS_RED_SUPPORT_DOMAIN_NUM (2+CFG_ELX_RADIO_24G_SSID_NUMBERS+CFG_ELX_RADIO_5G_SSID_NUMBERS)
#endif

enum _IF_TYPE{
    IF_TYPE_WAN=0,
    IF_TYPE_LAN,
    IF_TYPE_WLAN,
    IF_TYPE_IPTV,
    IF_TYPE_GUEST_NETWORK
};
struct config_handler_data
{
    INT32  interface_add_del;              /* interface_add_del=1 is add ; interface_add_del=0 is delete */
    INT32  isLAN;                     /* isLAN=1 is LAN port ; isLAN=0 is WAN port */
    INT8   interface[MAX_IFNAME_LEN]; /* interface name */
};

struct mac_passlist
{
    INT32       isExist;
    INT8        interface[MAX_IFNAME_LEN];
    INT8        dev_addr[6];
};

struct vlan_passlist
{
    INT32       isExist;
    INT8        interface[MAX_IFNAME_LEN];
    INT16       vlan_id;
    struct net_device  *dev;
};

struct vlan_if_info
{
    INT32       num_of_interface;
    struct net_device  *dev[MAX_LAN_IF_NUM];
};

struct spam_mail_info
{
    INT32		isExist;
    INT8		dev_addr[6];
    UINT32		packet_size;
    T_ULONG		reset_time;
    struct net_device  *dev;
};

#if CFG_ELX_DSC_CAPTIVE_PORTAL

#if CFG_ELX_NMS_SUPPORT_CAPTIVE_PORTAL_GROUP
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN
#define MAX_CAPTIVE_PORTAL_GROUP     (CFG_ELX_WLAN_RAIOD_NUMBERS*WLAN_SSID_NUM+1)
#else
#define MAX_CAPTIVE_PORTAL_GROUP     CFG_ELX_NMS_SUPPORT_CAPTIVE_PORTAL_GROUP
#endif  //
#else
#define MAX_CAPTIVE_PORTAL_GROUP     (CFG_ELX_WLAN_RAIOD_NUMBERS*WLAN_SSID_NUM+1)
#endif

#if CFG_ELX_NMS_SUPPORT_SYNC_ID
//for guest roaming
#define MAX_USERS_NUM	(512+100)
#else
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_MAC_BYPASS
#define MAX_USERS_NUM   (64*CFG_ELX_WLAN_RAIOD_NUMBERS*WLAN_SSID_NUM)
#else
#define MAX_USERS_NUM	(200)
#endif
#endif

#if CFG_ELX_DSC_EXTERNAL_CAPTIVE_PORTAL
#define MAX_EXTERNAL_USERS_NUM   MAX_USERS_NUM
#endif
#define AUTH_KEY_LEN (32)
#define CLOUD_AUTH_KEY_LEN (150)

#if CFG_ELX_DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
//#define MAX_USERS_ACCOUNT_NUM	(512)
#define MAX_USERS_ACCOUNT_NUM	(1500)
#endif

#if CFG_ELX_DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
#define MAX_SESSION_NUM 50
#endif

struct mem_info
{
	UINT8	is_auth;
	UINT32	group_id;
	UINT8	mac_addr[6];
#if CFG_ELX_DSC_CAPTIVE_PORTAL_MULTIPLE_SESSION
    UINT8   http_port_index;
    UINT32  http_src_port[MAX_SESSION_NUM];
    UINT32  http_dst_ip[MAX_SESSION_NUM];
    UINT8   https_port_index;
    UINT32  https_src_port[MAX_SESSION_NUM];
    UINT32  https_dst_ip[MAX_SESSION_NUM];
#else
	UINT32	dst_ip;
#endif
	UINT8	dst_mac[6];
};

#if CFG_ELX_DSC_EXTERNAL_CAPTIVE_PORTAL
struct external_mem_info
{
    UINT8   is_auth;
    UINT32  group_id;
    UINT8   mac_addr[6];
};
#endif
#if CFG_ELX_DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
struct user_info
{	
	UINT8	mac_addr[6];
	UINT8	type; //user type	
	UINT64	traffic_max;  //B
	UINT64	traffic_quota;  //B
};
#endif
#if CFG_ELX_DSC_RECORD_CLIENT_REQ
struct session_req
{	
	time_t req_t;
	UINT32 src_ip;
	UINT32 dst_ip;
	UINT16 dst_port;
	UINT8 src_mac[6];
};
struct client_req
{
	struct session_req si_req[NUM_RECORD_CLINENT_INFO];
	spinlock_t lock;
};
#endif
struct captive_portal_group_info
{
	UINT8	if_names[WLAN_SSID_NUM][MAX_IFNAME_LEN];
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL
    UINT32  external_redirect_port;
    UINT32  redirect_port;
    UINT32  external_redirect_port_2;
    UINT32  redirect_ip_2;
#else
	UINT32	redirect_http_port;
	UINT32	redirect_https_port;
#endif
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
    UINT8   paypal_ip_list_enable;
#endif
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || CFG_ELX_NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
    UINT8   social_login_ip_list_enable;
#endif
#if CFG_ELX_DSC_DNS_WALLEDGARDEN
	UINT64   walledgarden_type;
#endif
#if 0//CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_IP_FILTER
    UINT8   ip_filter_enable;
    UINT8   num_ip_filter_rule;
    UINT32  ip_list[64];
    UINT32  mask_list[64];
#endif
	UINT8	redirect_mac[6];
	UINT32	redirect_ip;
	UINT32	input_http_port;
	UINT32	input_https_port;
#if CFG_ELX_DSC_EXTERNAL_CAPTIVE_PORTAL
    UINT8   external_enable;
    UINT32  external_redirect_ip;
    UINT8   external_auth_type; // 0: authentication text
    UINT8   external_auth_key[AUTH_KEY_LEN+1];
    UINT32  external_input_http_port;
    UINT32  external_input_https_port;
#endif
#if CFG_ELX_DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL 
#if CFG_ELX_NMS_SUPPORT_CLOUD_AGENT_IN_AP_ROUTER
	UINT8	external_is_router;
#endif
#endif
};
#include <linux/ip.h>
#include <linux/tcp.h>
T_VOID compute_ip_checksum(struct iphdr* iphdrp);
T_VOID compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload);
#endif

#if CFG_ELX_DSC_REPLACE_VLAN_ID_BY_MAC
typedef struct _replace_vlan_id_entry_t
{
    unsigned char mac[6];
    unsigned short replace_vid;
    unsigned short original_vid;
} replace_vlan_id_entry_t;
#endif

int  dsc_init_driver(void);
void dsc_cleanup_driver(void);
int  dsc_driver(struct sk_buff *skb);
void update_wan_lan_if_list(void);
void update_vlan_info(void);

T_CHAR* ip_int_to_str(const T_UINT32 ip);
T_UINT32 ip_str_to_int(T_CHAR *ipaddr_str);
#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

 

#endif
