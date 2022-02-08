/** 
 *   @file dsc_cmd_tbl.c
 *   @brief This file prase the cmd from "proc", just like what we did to the CLI
 *   @author 
 *   @version 1
 *   @date  2013-0714
 *   @bug none
 *   @warning none
 */
/** -------------------------------------------------------------------------
 *               INCLUDE HEADER FILES                
  -------------------------------------------------------------------------*/
#include <dsc_main.h>
#include <dsc_config.h>
#include <dsc_cmd.h>
#include <ex_string.h>

static int isROOT = 0;
cli_data	g_cli_data;

cli_entry   vlan_menu[] =
{
    {OPM_ALL, "add", NULL, cmd_vlan_add, "add vlan info", "vlan add <id>:<interface>", AUTH_USER},
    {OPM_ALL, "del", NULL, cmd_vlan_del, "del vlan info", "vlan del <id>:<interface>", AUTH_USER},
    {OPM_ALL, "clean_all", NULL, cmd_vlan_clean, "clean vlan info", "vlan clean all", AUTH_USER},
    {OPM_ALL, "pass", NULL, cmd_vlan_pass, "vlan passthrough", "vlan pass [on/off]", AUTH_USER},
    {OPM_ALL, "help", vlan_menu, cmd_help, "List all command", "", AUTH_USER},
    {CMD_END_TAG}
};

cli_entry   lan_menu[] =
{
    {OPM_ALL, "add", NULL, cmd_lan_add, "add lan interface", "lan add <interface>", AUTH_USER},
    {OPM_ALL, "del", NULL, cmd_lan_del, "del lan interface", "lan del <interface>", AUTH_USER},
    {OPM_ALL, "ip", NULL, cmd_lan_ip, "add lan ip address", "lan ip <ip_address>", AUTH_USER},
    {OPM_ALL, "mac", NULL, cmd_lan_mac, "add lan MAC address", "lan ip <mac_address>", AUTH_USER},
    {OPM_ALL, "help", lan_menu, cmd_help, "List all command", "", AUTH_USER},
    {CMD_END_TAG}
};

cli_entry   wan_menu[] =
{
    {OPM_ALL, "add", NULL, cmd_wan_add, "add wan interface", "wan add <interface>", AUTH_USER},
    {OPM_ALL, "del", NULL, cmd_wan_del, "del wan interface", "wan del <interface>", AUTH_USER},
    {OPM_ALL, "help", wan_menu, cmd_help, "List all command", "", AUTH_USER},
    {CMD_END_TAG}
};

cli_entry   wlan_menu[] =
{
    {OPM_ALL, "add", NULL, cmd_wlan_add, "add wlan interface", "wlan add <interface>", AUTH_USER},
    {OPM_ALL, "del", NULL, cmd_wlan_del, "del wlan interface", "wlan del <interface>", AUTH_USER},
    {OPM_ALL, "help", wlan_menu, cmd_help, "List all command", "", AUTH_USER},
    {CMD_END_TAG}
};

cli_entry   mac_menu[] =
{
    {OPM_ALL, "add", NULL, cmd_mac_add, "add the mac of mac passthrough list", "mac add <mac> <interface>", AUTH_USER},
    {OPM_ALL, "del", NULL, cmd_mac_del, "del the mac of mac passthrough list", "mac del <mac> <interface>", AUTH_USER},
    {OPM_ALL, "clean_all", NULL, cmd_mac_clean, "clean the mac passthrough list", "mac clean_all", AUTH_USER},
    {OPM_ALL, "pass", NULL, cmd_mac_pass, "mac passthrough", "mac pass [on/off]", AUTH_USER},
    {OPM_ALL, "help", mac_menu, cmd_help, "List all command", "", AUTH_USER},
    {CMD_END_TAG}
};


#if DSC_CAPTIVE_PORTAL
cli_entry	captive_portal_menu[] =
{
    {OPM_ALL, "group", NULL, cmd_captive_portal_group, "captive portal group", "captive_portal group <number>", AUTH_USER},
	{OPM_ALL, "ctrl", NULL, cmd_captive_portal_pass, "captive portal ctrl", "captive_portal ctrl [on/off]", AUTH_USER},
	{OPM_ALL, "add_mac", NULL, cmd_captive_portal_mac, "add mac to captive portal", "captive_portal add_mac <mac>", AUTH_USER},
	{OPM_ALL, "add_if", NULL, cmd_captive_portal_add_if, "add interface to captive portal", "captive_portal add_if <index> <interface>", AUTH_USER},
	{OPM_ALL, "del_if", NULL, cmd_captive_portal_del_if, "remove interface to captive portal", "captive_portal del_if <index> <interface>", AUTH_USER},
	{OPM_ALL, "del_all_if", NULL, cmd_captive_portal_del_all_if, "remove all interface to captive portal", "captive_portal_del_all_if", AUTH_USER},
	{OPM_ALL, "redirect_mac", NULL, cmd_captive_portal_redirect_mac, "edit redirect mac to captive portal", "captive_portal redirect_mac <index> <mac>", AUTH_USER},
	{OPM_ALL, "redirect_ip", NULL, cmd_captive_portal_redirect_ip, "edit redirect ip address to captive portal", "captive_portal redirect_ip <index> <IP address>", AUTH_USER},
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL
    {OPM_ALL, "external_redirect_port", NULL, cmd_captive_portal_external_redirect_port, "edit external redirect port to captive portal", "captive_portal external_redirect_port <index> <port>", AUTH_USER},
    {OPM_ALL, "redirect_port", NULL, cmd_captive_portal_redirect_port, "edit redirect port to captive portal", "captive_portal redirect_port <index> <port>", AUTH_USER},
    {OPM_ALL, "external_redirect_sec_port", NULL, cmd_captive_portal_external_redirect_sec_port, "edit external redirect second port to captive portal", "captive_portal external_redirect_sec_port <index> <port>", AUTH_USER},
    {OPM_ALL, "redirect_sec_ip", NULL, cmd_captive_portal_redirect_sec_ip, "edit redirect second ip address to captive portal", "captive_portal redirect_sec_ip <index> <IP address>", AUTH_USER},
#else
	{OPM_ALL, "redirect_https_port", NULL, cmd_captive_portal_redirect_https_port, "edit redirect https portal to captive portal", "captive_portal redirect_https_port <index> <port>", AUTH_USER},
	{OPM_ALL, "redirect_http_port", NULL, cmd_captive_portal_redirect_http_port, "edit redirect http portal to captive portal", "captive_portal redirect_http_port <index> <port>", AUTH_USER},
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
    {OPM_ALL, "paypal_ip_list", NULL, cmd_captive_portal_paypal_ip_list, "captve portal paypal passcode allow list", "captive_portal paypal_ip_list <index> [on/off]", AUTH_USER},
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
    {OPM_ALL, "social_login_ip_list_update", NULL, cmd_captive_portal_social_login_ip_list_update, "captve portal social login update list", "captive_portal social_login_ip_list_update", AUTH_USER},
    {OPM_ALL, "social_login_ip_list", NULL, cmd_captive_portal_social_login_ip_list, "captve portal social login allow list", "captive_portal social_login_ip_list <index> [on/off]", AUTH_USER},
#endif
#if 0//WLAN_SUPPORT_URL_REDIRECT_IP_FILTER
    {OPM_ALL, "ip_filter_enable", NULL, cmd_captive_portal_ip_filter_enable, "captve portal IP filter ctrl", "captive_portal ip_filter_enable <index> [on/off]", AUTH_USER},
    {OPM_ALL, "num_ip_filter", NULL, cmd_captive_portal_num_ip_filter_rule, "edit ip filter number to captive portal", "captive_portal num_ip_filter <index> <num>", AUTH_USER},
    {OPM_ALL, "add_ip", NULL, cmd_captive_portal_add_ip, "add IP of IP filter to captive portal", "captive_portal add_ip <index> <ip_index> <ip> <mask>", AUTH_USER},
#endif
	{OPM_ALL, "input_http_port", NULL, cmd_captive_portal_input_http_port, "edit input http port to captive portal", "captive_portal input_http_port <index> <port>", AUTH_USER},
	{OPM_ALL, "input_https_port", NULL, cmd_captive_portal_input_https_port, "edit input https port to captive portal", "captive_portal input_https_port <index> <port>", AUTH_USER},
	{OPM_ALL, "mem_add_mac", NULL, cmd_captive_portal_mem_add_mac, "add mac to captive portal member", "captive_portal mem_add_mac <index> <mac>", AUTH_USER},
	{OPM_ALL, "mem_del_mac", NULL, cmd_captive_portal_mem_del_mac, "del mac to captive portal member", "captive_portal mem_del_mac <index> <mac>", AUTH_USER},
	{OPM_ALL, "mem_allow", NULL, cmd_captive_portal_mem_allow, "allow member", "captive_portal mem_allow <index> <mac>", AUTH_USER},
#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
	{OPM_ALL, "mem_allow_roaming", NULL, cmd_captive_portal_mem_allow_romaing, "allow romaing member", "captive_portal mem_allow_roaming <index> <mac> <user_tId>", AUTH_USER},
#endif
	{OPM_ALL, "mem_deny", NULL, cmd_captive_portal_mem_deny, "deny member", "captive_portal mem_deny <index> <mac>", AUTH_USER},
	{OPM_ALL, "mem_deny_group", NULL, cmd_captive_portal_mem_deny_group, "deny member of group", "captive_portal mem_deny_group <index>", AUTH_USER},
	{OPM_ALL, "mem_deny_all", NULL, cmd_captive_portal_mem_deny_all, "deny all member", "captive_portal mem_deny_all", AUTH_USER},
#if DSC_EXTERNAL_CAPTIVE_PORTAL
    {OPM_ALL, "ecp_enable", NULL, cmd_external_captive_portal_enable, "external captive portal enable", "captive_portal ecp_enable <index> <enable>", AUTH_USER},
    {OPM_ALL, "ecp_redirect_ip", NULL, cmd_external_captive_portal_redirect_ip, "edit redirect ip address to external captive portal", "captive_portal ecp_redirect_ip <index> <IP address>", AUTH_USER},
#if DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL
    {OPM_ALL, "ecp_redirect_ip", NULL, cmd_external_captive_portal_redirect_ip, "edit redirect ip address to external captive portal", "captive_portal ecp_redirect_ip <index> <IP address>", AUTH_USER},
#endif
    
    //     {OPM_ALL, "ecp_auth_type", NULL, cmd_external_captive_portal_auth_type, "edit authentication type to external captive portal", "captive_portal ecp_auth_type <index> <type>", AUTH_USER},
    {OPM_ALL, "ecp_auth_key", NULL, cmd_external_captive_portal_auth_key, "edit authentication key to external captive portal", "captive_portal ecp_auth_key <index> <key>", AUTH_USER},
    {OPM_ALL, "ecp_input_http_port", NULL, cmd_external_captive_portal_input_http_port, "edit input http port to external captive portal", "captive_portal ecp_input_http_port <index> <port>", AUTH_USER},
    {OPM_ALL, "ecp_input_https_port", NULL, cmd_external_captive_portal_input_https_port, "edit input https port to external captive portal", "captive_portal ecp_input_https_port <index> <port>", AUTH_USER},
#endif
#if DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL
    {OPM_ALL, "cloud_ecp_user_read", NULL, cmd_cloud_ecp_user_read, "cloud external captive portal user read", "captive_portal cloud_ecp_user_read", AUTH_USER},
#if NMS_SUPPORT_CLOUD_AGENT_IN_AP_ROUTER
	{OPM_ALL, "cloud_ecp_is_router", NULL, cmd_external_captive_portal_is_router_mode, "cloud external captive portal is router", "captive_portal cloud_ecp_is_router", AUTH_USER},
#endif
#endif
#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION	
	{OPM_ALL, "user_max", NULL, cmd_captive_portal_user_max, "set user max traffic", "captive_portal user_max <user_tId> <value>", AUTH_USER},	
	{OPM_ALL, "user_quota", NULL, cmd_captive_portal_user_quota, "set user traffic user_quota", "captive_portal user_quota <user_tId> <value>", AUTH_USER},
	{OPM_ALL, "user_type", NULL, cmd_captive_portal_user_type, "set user type", "captive_portal user_type <user_tId> <value>", AUTH_USER},
	{OPM_ALL, "user_mac_add", NULL, cmd_captive_portal_user_mac_add, "add user mac", "captive_portal user_mac_add <mac> <user_tId>", AUTH_USER},
	{OPM_ALL, "user_mac_rm", NULL, cmd_captive_portal_user_mac_rm, "rm user mac", "captive_portal user_mac_rm <user_tId>", AUTH_USER},
	{OPM_ALL, "user_quota_read", NULL, cmd_captive_portal_user_quota_read, "user quota read", "captive_portal user_quota_read <user_tId>", AUTH_USER},
#endif
#if DSC_DNS_WALLEDGARDEN
	{OPM_ALL, "assign_walledgarden", NULL, cmd_captive_portal_assign_walledgarden, "captve portal asign walledgarden", "captive_portal asign_walledgarden <index> <walledgarden_group>", AUTH_USER},
#endif
	{OPM_ALL, "help", captive_portal_menu, cmd_help, "List all command", "", AUTH_USER},
	{CMD_END_TAG}
};
#endif

#if DSC_DNS_REDIRECT
cli_entry	dns_redirect_menu[] =
{
    {OPM_ALL, "ctrl", NULL, cmd_dns_redirect_ctrl, "dns redirect ctrl", "dns_redirect ctrl [on/off]", AUTH_USER},
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
	{OPM_ALL, "add_domain_name", NULL, cmd_dns_redirect_add_multiple_domain_name, "add domain name for dns redirect (support multiple)", "dns_redirect add_domain_name <name> <index>", AUTH_USER},
#else
	{OPM_ALL, "add_domain_name", NULL, cmd_dns_redirect_add_domain_name, "add domain name", "dns_redirect add_domain_name <name>", AUTH_USER},
#endif
	{OPM_ALL, "help", dns_redirect_menu, cmd_help, "List all command", "", AUTH_USER},
	{CMD_END_TAG}
};
#endif
#if DSC_DNS_WALLEDGARDEN
cli_entry	walledgarden_menu[] =
{
	{OPM_ALL, "add_walledgarden", NULL, cmd_add_walledgarden, "add walledgarden group", "walled_garden add_walledgarden <walledgarden group>(-1 will default all)", AUTH_USER},
	{OPM_ALL, "help", walledgarden_menu, cmd_help, "List all command", "", AUTH_USER},
	{CMD_END_TAG}
};
#endif


cli_entry	cmd_table[] = 
{
    {OPM_ALL, "port_vlan_id", NULL, cmd_port_vlan_id, "add port vlan id info", "port_vlan_id <LAN_4>,<LAN_3>,<LAN_2>,<LAN_1>,<SSID_1>,<SSID_2>,<SSID_3>,<SSID_4>", AUTH_USER},
    {OPM_ALL, "vlan", vlan_menu, cli_get_next_table, "vlan info", "vlan [add|del|clean_all|pass]", AUTH_USER},
    {OPM_ALL, "lan", lan_menu, cli_get_next_table, "lan info", "lan [add|del|ip]", AUTH_USER},
    {OPM_ALL, "wan", wan_menu, cli_get_next_table, "wan info", "wan [add|del]", AUTH_USER},
    {OPM_ALL, "wlan", wlan_menu, cli_get_next_table, "wlan info", "wlan [add|del]", AUTH_USER},
    {OPM_ALL, "pppoe", NULL, cmd_pppoe, "PPPoE passthrough", "pppoe [on/off]", AUTH_USER},
    {OPM_ALL, "ipv6", NULL, cmd_ipv6, "IPv6 passthrough", "ipv6 [on/off]", AUTH_USER},
    {OPM_ALL, "mcast_pass", NULL, cmd_mcast_pass, "multicast packet passthrough", "mcast_pass [on/off]", AUTH_USER},
    {OPM_ALL, "mcast_transfer_reverse", NULL, cmd_mcast_transfer_reverse, "convert unicast packet into multicast packet", "mcast_transfer_reverse [on/off]", AUTH_USER},
    {OPM_ALL, "mac", mac_menu, cli_get_next_table, "mac passthrough info", "mac [add|del|pass]", AUTH_USER},

#if NMS_SUPPORT_GRAT_ARP
	{OPM_ALL, "arp", NULL, cmd_arp, "arp", "arp [on/off]", AUTH_USER},
#endif
#if DSC_CAPTIVE_PORTAL
	{OPM_ALL, "captive_portal", captive_portal_menu, cli_get_next_table, "captive_portal info", "captive_portal [add|del|clean_all]", AUTH_USER},
#endif

#if DSC_DNS_REDIRECT
	{OPM_ALL, "dns_redirect", dns_redirect_menu, cli_get_next_table, "dns_redirect info", "dns_redirect [add]", AUTH_USER},
#endif
#if DSC_DNS_WALLEDGARDEN
	{OPM_ALL, "walledgarden", walledgarden_menu, cli_get_next_table, "walledgarden info", "walledgarden [add]", AUTH_USER},
#endif
    {OPM_ALL, "default", NULL, cmd_default, "default", "Init all parameters", AUTH_USER},

    {OPM_ALL, "help", cmd_table, cmd_help, "List all command", "", AUTH_USER},
    {CMD_END_TAG}
};

/*****************************************************************************/
/**
 *  @brief cli_get_next_token
 *  @param cli_data* cli_data
 *  @param T_INT32 idx
 *  @return T_CHAR* 
 */
__inline T_CHAR* cli_get_next_token(const cli_data* cli_data, const T_INT32 idx)
{
    return (cli_data->argc-idx) > 0 ? cli_data->tokens[cli_data->cur_lv+(idx+1)].token : "(null)";
}


/*****************************************************************************/
/**
 * @brief cli_get_next_table
 * @param cli_data* cli_data
 * @return T_VOID
 */
cli_status cli_get_next_table(T_VOID* priv, cli_data* cli_data)
{
	cli_entry *pTable = (cli_entry *) priv;
	T_INT32 cnt = 0;
	T_INT32 current_level;

	T_CHAR *usr_token;
	if(cli_data->argc < 0 || pTable == NULL)
	{
		return CLI_NO_MATCH;
	}
	current_level = cli_data->cur_lv = (cli_data->token_len -cli_data->argc);
	usr_token = (cli_data->argc > 0) ? cli_data->tokens[current_level].token : "";
	while(CMD_END_TAG != pTable[cnt].opMode)
	{
        if(strcmp(usr_token, pTable[cnt].cmdName) == 0)
        {
            if(pTable[cnt].opMode & cli_data->mode)
            {
                --(cli_data->argc);
                cli_data->tokens[current_level].entry = &pTable[cnt];
                switch(pTable[cnt].authority)
                {
                    case AUTH_USER:
                        return pTable[cnt].handler(pTable[cnt].priv, cli_data);
                        break;
                    case AUTH_ADMIN:    /* Compare if the user ID is "ROOT", otherwise auth fail */
                        if(!isROOT)
                        {
                            return CLI_NO_AUTH;
                        }
                        return pTable[cnt].handler(pTable[cnt].priv, cli_data);
                        break;
                    case AUTH_ANY:  /* Not use AUTH_ANY */

                    default :
                        return CLI_NO_AUTH;
                }
            }
        }
        cnt++;
	}
    return CLI_NO_MATCH;
}

/*****************************************************************************/
/**
 * @brief cli_handle
 * @param T_CHAR* input
 * @return T_VOID
 */ 
T_VOID cli_handle(T_CHAR* input)
{
    T_CHAR *token;

    memset(&g_cli_data, 0, sizeof(g_cli_data));
    g_cli_data.token_len = 0;
    g_cli_data.mode = OPM_ALL;
    token = strtok(input, "\t \r\n");
    while(token && g_cli_data.token_len < MAX_TOKEN_STACK_LEN)
    {
        g_cli_data.tokens[g_cli_data.token_len++].token = token;
        token = strtok(NULL, "\t \r\n");
    }
    g_cli_data.argc = g_cli_data.token_len;
    g_cli_data.cur_lv = 0;
    switch(cli_get_next_table(cmd_table, &g_cli_data))
    {
        case CLI_OK:
            break;
        case CLI_PARAMS_ERR:
            printk("Parameter error!\n");
            break;
        case CLI_NO_MATCH:
            /** No Match same as default */
            printk("The command has no been found\n");
            break;
        default:
            printk("\n");
            break;
    }
}
