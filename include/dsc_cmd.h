#ifndef _DSC_CLI_H
#define _DSC_CLI_H

#include <gconfig.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CMD_END_TAG 0xed122aff
#define MAX_TOKEN_STACK_LEN	64
#define CLI_TITLE_WIDTH     16
#define CLI_DEFAULT_WIDTH   60  // show options use
#define CLI_RESERVE_WIDTH   8   // show options use
#define CLI_TITLE_SPACE     "                          "  // 26 space
#define CLI_CMD_NAME        "%22s -- %s\n"
#define CLI_CMD_USAGE       "%s%s\n", CLI_TITLE_SPACE

typedef enum {
	CLI_OK = 0,
	CLI_NOTHING,
    CLI_NO_MATCH,
	CLI_PARAMS_ERR,
    CLI_NO_AUTH,
    CLI_EXIT
} cli_status;

typedef enum {
	OPM_ALL = 1		/** should be > 0 */
} opmode_t;

typedef enum {
	AUTH_ANY = 1,
    AUTH_USER = 3,
    AUTH_ADMIN = 9
} auth_t;

struct cli_data_t;

typedef struct cli_entry_t
{
	T_UINT32 opMode;
	const T_CHAR *cmdName;
	T_VOID *priv;
	cli_status (*handler)(T_VOID *priv, struct cli_data_t *cli_data);
	const T_CHAR *description;
	const T_CHAR *usage;
	T_INT32 authority;		/** use for hidden for command */
} cli_entry;

typedef struct cli_entry_list_t
{
	T_CHAR *token;		/** token value */
	cli_entry *entry;	/** pointer to cli_entry belong to this token */
} cli_entry_list;

/** save params during parsing - use cli_param(cmdName) to find the parameter instead of using the index of the total command */
typedef struct cli_param_list_t
{
	const T_CHAR *cmdName;	/**	the key for search the value - e.g. CMD_TYPE_READIO */
	T_CHAR *token;			/** token value */
} cli_param_list;

/** save params during parsing - use cli_cmd_list.type for find the value instead of using the index of the total command */
typedef struct cli_cmd_list_t
{
	T_UINT32 type;		/** the key for search the value - e.g. CMD_TYPE_READIO */
	T_UINT32 value;		/** type value - e.g. TYPE_READIO_24G, TYPE_READIO_5G */
} cli_cmd_list;

typedef struct cli_data_t
{
	cli_entry_list	tokens[MAX_TOKEN_STACK_LEN];
	T_INT32			cur_lv;			/** current level of tokens array */
	T_INT32			argc;			/** remain how many tokens for current level */
	T_INT32			token_len;		/**	Total tokens that cli get */
	T_INT32			mode;
	cli_param_list	params[MAX_TOKEN_STACK_LEN];
	T_BOOL			param;			/** Is this argument parameter */
	T_BOOL			end;			/** command end for help */
	const T_CHAR	*description;	/** remeber previous description for help */
	cli_cmd_list	cmds[MAX_TOKEN_STACK_LEN];
} cli_data;

T_VOID cli_handle(T_CHAR *input);
cli_status cli_get_next_table(T_VOID *priv, cli_data *cli_data);
T_CHAR *cli_get_next_token(const cli_data *cli_data, const T_INT32 idx);

cli_status cmd_help(T_VOID *priv, cli_data *cli_data);

cli_status cmd_port_vlan_id(T_VOID *priv, cli_data *cli_data);

cli_status cmd_vlan_add(T_VOID *priv, cli_data *cli_data);
cli_status cmd_vlan_del(T_VOID *priv, cli_data *cli_data);
cli_status cmd_vlan_clean(T_VOID *priv, cli_data *cli_data);
cli_status cmd_vlan_pass(T_VOID *priv, cli_data *cli_data);

cli_status cmd_lan_add(T_VOID *priv, cli_data *cli_data);
cli_status cmd_lan_del(T_VOID *priv, cli_data *cli_data);
cli_status cmd_lan_mac(T_VOID *priv, cli_data *cli_data);
cli_status cmd_lan_ip(T_VOID *priv, cli_data *cli_data);
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_VLAN
cli_status cmd_lan_additional_ip(T_VOID *priv, cli_data *cli_data);
#endif

cli_status cmd_wan_add(T_VOID *priv, cli_data *cli_data);
cli_status cmd_wan_del(T_VOID *priv, cli_data *cli_data);
#if CFG_ELX_DSC_WAN_PKT_HAS_VLANID
cli_status cmd_wan_vlan_id(T_VOID *priv, cli_data *cli_data);
#endif
#if SUPPORT_RAETH_WANMAC
cli_status cmd_wan_mac(T_VOID *priv, cli_data *cli_data);
#endif

cli_status cmd_wlan_add(T_VOID *priv, cli_data *cli_data);
cli_status cmd_wlan_del(T_VOID *priv, cli_data *cli_data);

cli_status cmd_pppoe(T_VOID *priv, cli_data *cli_data);

cli_status cmd_ipv6(T_VOID *priv, cli_data *cli_data);

#if CFG_ELX_DSC_IPV6_MCAST
cli_status cmd_iptv_add(T_VOID *priv, cli_data *cli_data);
cli_status cmd_iptv_del(T_VOID *priv, cli_data *cli_data);
#endif

#if CFG_ELX_DSC_RATECTRL
cli_status cmd_rate_ctrl(T_VOID *priv, cli_data *cli_data);
cli_status cmd_rate_max(T_VOID *priv, cli_data *cli_data);
#endif

cli_status cmd_mcast_pass(T_VOID *priv, cli_data *cli_data);
cli_status cmd_mcast_transfer_reverse(T_VOID *priv, cli_data *cli_data);
#if CFG_ELX_WLAN_SUPPORT_ZWDFS 
cli_status cmd_zwdfs_drop(T_VOID *priv, cli_data *cli_data);
#endif
#if defined(FOR_RALINK_PLATFORM)  && SUPPORT_RAETH_MCAST_ONOFF
cli_status cmd_raeth_mcast(T_VOID *priv, cli_data *cli_data);
#endif

#if CFG_ELX_DSC_ETH_IGMP_SNOOPING
cli_status cmd_igmp_snooping(T_VOID *priv, cli_data *cli_data);
#endif

#if CFG_ELX_WLAN_GUEST_NETWORK && CFG_ELX_IPV6
cli_status cmd_ipv6_guest_network_add(T_VOID *priv, cli_data *cli_data);
cli_status cmd_ipv6_guest_network_del(T_VOID *priv, cli_data *cli_data);
cli_status cmd_ipv6_guest_network_vlan_id(T_VOID *priv, cli_data *cli_data);
cli_status cmd_ipv6_guest_network_pass(T_VOID *priv, cli_data *cli_data);
#endif

cli_status cmd_mac_add(T_VOID *priv, cli_data *cli_data);
cli_status cmd_mac_del(T_VOID *priv, cli_data *cli_data);
cli_status cmd_mac_clean(T_VOID *priv, cli_data *cli_data);
cli_status cmd_mac_pass(T_VOID *priv, cli_data *cli_data);

#if CFG_ELX_WLAN_GUEST_NETWORK_SPAM_MAIL
cli_status cmd_spam_mail_add(T_VOID *priv, cli_data *cli_data);
cli_status cmd_spam_mail_del(T_VOID *priv, cli_data *cli_data);
cli_status cmd_spam_mail_clean(T_VOID *priv, cli_data *cli_data);
cli_status cmd_spam_mail_pass(T_VOID *priv, cli_data *cli_data);
#endif

#if CFG_ELX_DSC_DHCP || CFG_ELX_DSC_DOMAIN_REDIRECT
cli_status cmd_dhcp_dns(T_VOID *priv, cli_data *cli_data);
cli_status cmd_dhcp_dns_add_mac(T_VOID *priv, cli_data *cli_data);
#if CFG_ELX_DUAL_LAN_BRIDGE_DEV
cli_status cmd_sys_opmode(T_VOID *priv, cli_data *cli_data);
cli_status cmd_dual_band_if_ip(T_VOID* priv, cli_data* cli_data);
cli_status cmd_dual_band_if_mac(T_VOID* priv, cli_data* cli_data);
#if CFG_ELX_OPMODE_UNIVERSAL_REPEATER && CFG_ELX_SET_BRIDGE_IF_BASE_ON_PROFILE
cli_status cmd_conn_status(T_VOID *priv, cli_data *cli_data);
#endif
cli_status cmd_connection_case(T_VOID *priv, cli_data *cli_data);
#if CFG_ELX_NETWORK_AUTO_DHCP
cli_status cmd_is_dual_brigde_enable(T_VOID *priv, cli_data *cli_data);
#endif
#endif
#if CFG_ELX_DSC_DOMAIN_REDIRECT
cli_status cmd_domain_name(T_VOID *priv, cli_data *cli_data);
cli_status cmd_domain_redirect(T_VOID *priv, cli_data *cli_data);
#endif
#endif

#if CFG_ELX_NMS_SUPPORT_GRAT_ARP
cli_status cmd_arp(T_VOID *priv, cli_data *cli_data);
#endif
#if CFG_ELX_DSC_CAPTIVE_PORTAL
cli_status cmd_captive_portal_group(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_pass(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_mac(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_add_if(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_del_if(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_del_all_if(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_redirect_mac(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_redirect_ip(T_VOID *priv, cli_data *cli_data);
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL
cli_status cmd_captive_portal_external_redirect_port(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_redirect_port(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_external_redirect_sec_port(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_redirect_sec_ip(T_VOID *priv, cli_data *cli_data);
#else
cli_status cmd_captive_portal_redirect_http_port(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_redirect_https_port(T_VOID *priv, cli_data *cli_data);
#endif
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
cli_status cmd_captive_portal_paypal_ip_list(T_VOID* priv, cli_data* cli_data);
#endif
#if CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || CFG_ELX_NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
cli_status cmd_captive_portal_social_login_ip_list_update(T_VOID* priv, cli_data* cli_data);
cli_status cmd_captive_portal_social_login_ip_list(T_VOID* priv, cli_data* cli_data);
#endif
#if 0//CFG_ELX_WLAN_SUPPORT_URL_REDIRECT_IP_FILTER
cli_status cmd_captive_portal_ip_filter_enable(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_num_ip_filter_rule(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_add_ip(T_VOID *priv, cli_data *cli_data);
#endif
cli_status cmd_captive_portal_input_http_port(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_input_https_port(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_mem_add_mac(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_mem_del_mac(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_mem_allow(T_VOID *priv, cli_data *cli_data);
#if CFG_ELX_DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
cli_status cmd_captive_portal_mem_allow_romaing(T_VOID* priv, cli_data* cli_data);
#endif
cli_status cmd_captive_portal_mem_deny(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_mem_deny_group(T_VOID *priv, cli_data *cli_data);
cli_status cmd_captive_portal_mem_deny_all(T_VOID* priv, cli_data* cli_data);

#if CFG_ELX_DSC_EXTERNAL_CAPTIVE_PORTAL
cli_status cmd_external_captive_portal_enable(T_VOID *priv, cli_data *cli_data);
cli_status cmd_external_captive_portal_redirect_ip(T_VOID *priv, cli_data *cli_data);
// cli_status cmd_external_captive_portal_auth_type(T_VOID *priv, cli_data *cli_data);
cli_status cmd_external_captive_portal_auth_key(T_VOID *priv, cli_data *cli_data);
cli_status cmd_external_captive_portal_input_http_port(T_VOID *priv, cli_data *cli_data);
cli_status cmd_external_captive_portal_input_https_port(T_VOID *priv, cli_data *cli_data);
#endif

#if CFG_ELX_DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL
cli_status cmd_cloud_ecp_user_read(T_VOID *priv, cli_data *cli_data);
cli_status cmd_external_captive_portal_is_router_mode(T_VOID* priv, cli_data* cli_data);
#endif

#if CFG_ELX_DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
cli_status cmd_captive_portal_user_max(T_VOID* priv, cli_data* cli_data);
cli_status cmd_captive_portal_user_quota(T_VOID* priv, cli_data* cli_data);
cli_status cmd_captive_portal_user_type(T_VOID* priv, cli_data* cli_data);
cli_status cmd_captive_portal_user_mac_add(T_VOID* priv, cli_data* cli_data);
cli_status cmd_captive_portal_user_mac_rm(T_VOID* priv, cli_data* cli_data);
cli_status cmd_captive_portal_user_quota_read(T_VOID* priv, cli_data* cli_data);
#endif
#if CFG_ELX_DSC_DNS_WALLEDGARDEN
cli_status cmd_captive_portal_assign_walledgarden(T_VOID* priv, cli_data* cli_data);
#endif
#endif
#if CFG_ELX_DSC_DNS_WALLEDGARDEN
cli_status cmd_add_walledgarden(T_VOID* priv, cli_data* cli_data);
#endif
#if CFG_ELX_DSC_DNS_REDIRECT
cli_status cmd_dns_redirect_ctrl(T_VOID *priv, cli_data *cli_data);
#if CFG_ELX_DSC_DNS_REDIRECT_MULTI_DOMAIN
cli_status cmd_dns_redirect_add_multiple_domain_name(T_VOID *priv, cli_data *cli_data);
#else
cli_status cmd_dns_redirect_add_domain_name(T_VOID *priv, cli_data *cli_data);
#endif
#endif

#if CFG_ELX_NETWORK_VLAN_FORWARD
cli_status cmd_vlan_forward_ctrl(T_VOID* priv, cli_data* cli_data);
cli_status cmd_vlan_forward_new_id(T_VOID* priv, cli_data* cli_data);
cli_status cmd_vlan_forward_old_id(T_VOID* priv, cli_data* cli_data);
cli_status cmd_vlan_forward_ip(T_VOID* priv, cli_data* cli_data);
cli_status cmd_vlan_forward_port(T_VOID* priv, cli_data* cli_data);
#endif

#if CFG_ELX_DSC_REPLACE_VLAN_ID_BY_MAC
cli_status cmd_vlan_replace_vid_ctrl(T_VOID* priv, cli_data* cli_data);
cli_status cmd_vlan_replace_vid_add_mac(T_VOID *priv, cli_data *cli_data);
cli_status cmd_vlan_replace_vid_del_mac(T_VOID *priv, cli_data *cli_data);
cli_status cmd_vlan_replace_vid_clean(T_VOID *priv, cli_data *cli_data);
#endif

#if CFG_ELX_DSC_REPLACE_VLAN_PCP_BY_SSID
cli_status cmd_vlan_replace_pcp(T_VOID *priv, cli_data *cli_data);
#endif

#if CFG_ELX_DSC_DHCP_BCAST_TO_UCAST
cli_status cmd_dhcp_bc2uc(T_VOID *priv, cli_data *cli_data);
#endif
cli_status cmd_default(T_VOID *priv, cli_data *cli_data);

#ifdef __cplusplus
}
#endif

#endif
