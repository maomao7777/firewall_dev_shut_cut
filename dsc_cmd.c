/** 
 *   @file dsc_cmd.c
 *   @brief This file prase the cmd from "proc", just like what we did to the CLI
 *   @author 
 *   @version 
 *   @date  
 *   @bug 
 *   @warning 
 */
/** -------------------------------------------------------------------------
 *               INCLUDE HEADER FILES                
  -------------------------------------------------------------------------*/
#include <gconfig.h>
#include <dsc_main.h>
#include <dsc_config.h>
#include <dsc_cmd.h>
#if DSC_DNS_WALLEDGARDEN
#include <dsc_walledgarden_handler.h>
#endif
extern T_UINT32 is_updating_wan_lan_if_list;
extern T_UINT32 wan_if_num;
extern T_UINT8  wan_if_names[MAX_WAN_IF_NUM][MAX_IFNAME_LEN];
extern struct net_device *wan_if_list[MAX_WAN_IF_NUM];

extern T_UINT32 lan_if_num;
extern T_UINT8  lan_if_names[MAX_LAN_IF_NUM][MAX_IFNAME_LEN];
extern struct net_device *lan_if_list[MAX_LAN_IF_NUM];

extern T_UINT32 wlan_if_num;
extern T_UINT8  wlan_if_names[MAX_WLAN_IF_NUM][MAX_IFNAME_LEN];
extern struct net_device *wlan_if_list[MAX_WLAN_IF_NUM];

extern UINT32 is_wan_mac_cloned;
extern UINT32 vlan_id;

extern T_UINT32 is_vlan_pass_through;
extern T_UINT32 vlan_if_num;
extern struct vlan_if_info  vlan_if_info[MAX_VLAN_ID];
extern struct vlan_passlist vlan_pass_table[MAX_VLAN_PASS_TABLE];

extern struct net_device *ssid2If;
extern struct net_device *eth_lan_if;
extern T_UINT32 lan_ip_address;
extern UINT8 lan_mac_address[ETH_ALEN];
extern T_UINT32 port_vlan_id_list[MAX_PORT_NUM];
extern T_UINT32 is_pppoe_pass_through;
extern T_UINT32 is_ipv6_paas_through;
extern T_UINT32 is_mcast_pkt_pass_through;
extern T_UINT32 is_mcast_trans_reverse;
extern T_UINT32 is_mac_pass_through;
extern T_UINT32 mac_if_num;
extern struct mac_passlist mac_pass_table[MAX_MAC_PASS_TABLE];

#if DSC_CAPTIVE_PORTAL
extern T_UINT32 is_captive_portal;
extern struct captive_portal_group_info group[MAX_CAPTIVE_PORTAL_GROUP];
extern UINT32 g_captive_portal_group;
extern struct mem_info mem[MAX_USERS_NUM];
extern T_UINT32 mem_index;
extern UINT8 dev_mac[ETH_ALEN];

#if DSC_EXTERNAL_CAPTIVE_PORTAL
extern struct external_mem_info external_mem[MAX_EXTERNAL_USERS_NUM];
extern T_UINT32 external_mem_index;
#endif

#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
extern struct user_info user[MAX_USERS_ACCOUNT_NUM];
#endif
#endif
#if WLAN_SUPPORT_URL_REDIRECT_VLAN
extern T_UINT32 add_lan_ip[ADDITIONAL_LAN_IP_NUM];
extern T_UINT8  add_ip_idx;
#endif

#if DSC_DNS_REDIRECT
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
extern int dns_redirect;
extern char dns_domain_name[DNS_RED_SUPPORT_DOMAIN_NUM][64+1];
extern char netbios_name[DNS_RED_SUPPORT_DOMAIN_NUM][64+1];
#else
extern char dns_domain_name[32+1];
extern char netbios_name[64+1];
extern int dns_redirect;
#endif
#endif

#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
extern T_UINT32 paypal_ip[PASSCODE_PAYPAL_DOMAIN_NUMBER];
extern T_INT paypal_ip_count;
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
extern T_UINT32 social_login_ip[SOCIAL_LOGIN_DOMAIN_NUMBER+16]; //FB known ip is num of 16
extern T_INT social_login_ip_count;
#endif
#if DSC_DNS_WALLEDGARDEN
extern struct walledgarden walled_garden[MAX_SUPPORT_WALLEDGARDEN_GROUP];
extern struct wgHashTbl wg_hashtbl;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
        #define DEV_GET(x) __dev_get_by_name(x)
#else
        #define DEV_GET(x) __dev_get_by_name(&init_net,x)
#endif

static char *wl_interface_str[]={
    "ra0",
    "ra1",
    "ra2",
    "ra3",
};
#if 0
#define dbg_printk	printk
#else
// #define dbg_printk(x...) do() {}while(0)
#define dbg_printk(a...) do {} while(0)
#endif
/*****************************************************************************/
/**
 *  @brief hex_to_i
 *  @return unsigned int
 */
const T_CHAR hex_mapping[]={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',};
static T_UINT32 hex_to_i(const T_CHAR *user_buffer, T_UINT32 max_len, T_UINT32 *num)
{
    T_UINT32 i, j;
    T_CHAR c;

    *num = 0;

    if(!user_buffer) return 0;

    for(i = 0; i < max_len; i++)
    {
        c = user_buffer[i];
        for(j = 0; j < 16; j++)
        {
            if(hex_mapping[j] == c) break;
        }
        if(j == 16) return 0;
        *num = (*num<<4) + j;
    }
    return 0;
}
/*****************************************************************************/
/**
 * *  @brief set local rules
 * *  @param T_VOID
 * *  @return T_VOID
 * */
T_INT mac_str_to_mac_bin(T_UINT8 dst[6], const T_CHAR *macStr)
{
    T_INT i;
    T_UINT32 mac[6];

    if(sscanf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
    {
        goto mac_str_to_mac_bin_ok;
    }
    if(sscanf(macStr, "%02X%02X%02X%02X%02X%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
    {
        goto mac_str_to_mac_bin_ok;
    }
    return 0;

mac_str_to_mac_bin_ok:
    memset(dst, 0, 6);
    for(i = 0; i < 6 ; i++)
    {
        dst[i] = mac[i];
    }
    return 1;
}
/*****************************************************************************/
/**
 * *  @brief set local rules
 * *  @param T_VOID
 * *  @return T_VOID
 * */
T_INT mac_bin_to_mac_str(T_CHAR* dst_str, const T_UINT8 mac_bin[6])
{
        if (!dst_str)
        {
            return 0;
        }
    
        return sprintf(dst_str, "%02X:%02X:%02X:%02X:%02X:%02X", 
                                   mac_bin[0], mac_bin[1], mac_bin[2], mac_bin[3], mac_bin[4], mac_bin[5]);
}

/*****************************************************************************/
/**
 *  @brief x_atoi
 *  @param const char *name
 *  @return int
 */ 
static T_INT x_atoi(const T_CHAR *name)
{
    T_INT val = 0;

    for(;; name++)
    {
        switch(*name)
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                val = 10 * val + (*name - '0');
                break;
            default:
                return val;
        }
    }
}
/*****************************************************************************/
/**
 *  @brief update_vlan_info
 *  @param T_VOID
 *  @return T_VOID
 */
T_VOID update_vlan_info(T_VOID)
{
    T_UINT32 i;

    memset(&vlan_if_info, 0x0, sizeof(vlan_if_info));
    for(i = 0; i < MAX_PORT_NUM; i++)
    {
        if(port_vlan_id_list[i] == 0)
        {
            continue;
        }
        if(i < 4)
        {
            vlan_if_info[port_vlan_id_list[i]].dev[vlan_if_info[port_vlan_id_list[i]].num_of_interface] = DEV_GET("eth2");
            vlan_if_info[port_vlan_id_list[i]].num_of_interface++;
        }
        else
        {
            vlan_if_info[port_vlan_id_list[i]].dev[vlan_if_info[port_vlan_id_list[i]].num_of_interface] = DEV_GET(wl_interface_str[i-4]);
            vlan_if_info[port_vlan_id_list[i]].num_of_interface++;
        }
    }
}

/*****************************************************************************/
/**
 *  @brief add_vlan_id_list
 *  @param vlan_passlist
 *  @return T_INT
 */
T_INT add_vlan_id_list(struct vlan_passlist *data)
{
    T_UINT32 i;
    for(i = 0; i < MAX_VLAN_PASS_TABLE; i++)
    {
        /* add Vlan ID for interface */
        if(data->isExist)
        {
            if(!vlan_pass_table[i].isExist)
            {
                strcpy(vlan_pass_table[i].interface, data->interface);
                vlan_pass_table[i].vlan_id = data->vlan_id;
                vlan_pass_table[i].isExist = 1;
                vlan_pass_table[i].dev = DEV_GET(vlan_pass_table[i].interface);
                vlan_if_num++;
                break;
            }
        }
        else /* delete Vlan ID for interface */
        {
            if(strcmp(vlan_pass_table[i].interface, data->interface) == 0 && vlan_pass_table[i].vlan_id == data->vlan_id)
            {
                memcpy(&vlan_pass_table[i], &vlan_pass_table[vlan_if_num-1], sizeof(vlan_pass_table[0]));
                vlan_pass_table[vlan_if_num-1].isExist = 0;
                vlan_if_num--;
                break;
            }
        }
    }
    return 0;
}

/*****************************************************************************/
/**
 *  @brief update_wan_lan_if_list
 *  @param T_VOID
 *  @return T_VOID
 */
T_VOID update_wan_lan_if_list()
{
    T_UINT32 i;

    for(i = 0; i < lan_if_num; i++)
    {
        if(strcmp("ra1", lan_if_names[i]) == 0)
        {
            ssid2If = DEV_GET("ra1");

            if(ssid2If && !(ssid2If->flags & IFF_UP))
            {
                ssid2If = NULL;
            }
        }
        if(strcmp("eth2.1", lan_if_names[i]) == 0)
        {
            eth_lan_if = DEV_GET("eth2.1");

            if(eth_lan_if && !(eth_lan_if->flags & IFF_UP))
            {
                eth_lan_if = NULL;
            }
        }

        lan_if_list[i] = DEV_GET(lan_if_names[i]);
        dbg_printk("Register LAN%d dev [%s] ", i, lan_if_names[i]);

        if(!lan_if_list[i])
        {
            dbg_printk("failed. Dev does not exist!!!\n");
        }
        else if(!(lan_if_list[i]->flags & IFF_UP))
        {
            dbg_printk("OK. But Interface is Down\n");
            lan_if_list[i] = NULL;
        }
        else
        {
            dbg_printk("OK.\n");
        }
    }

    for(i = 0; i < wan_if_num; i++)
    {
        wan_if_list[i] = DEV_GET(wan_if_names[i]);
        dbg_printk("Register WAN%d dev [%s] ", i, wan_if_names[i]);

        if(!wan_if_list[i])
        {
            dbg_printk("failed. Dev does not exist!!!\n");
        }
        else if(!(wan_if_list[i]->flags & IFF_UP))
        {
            dbg_printk("OK. But Interface is Down\n");
            wan_if_list[i] = NULL;
        }
        else
        {
            dbg_printk("OK.\n");
        }
    }

    for(i = 0; i < wlan_if_num; i++)
    {
        wlan_if_list[i] = DEV_GET(wlan_if_names[i]);
        dbg_printk("Register WLAN%d dev [%s] ", i, wlan_if_names[i]);

        if(!wlan_if_list[i])
        {
            dbg_printk("failed. Dev does not exist!!!\n");
        }
        else if(!(wlan_if_list[i]->flags & IFF_UP))
        {
            dbg_printk("OK. But Interface is Down\n");
            wlan_if_list[i] = NULL;
        }
        else
        {
            dbg_printk("OK.\n");
        }
    }
}

#define LOCK_WANLAN_IF_LIST     is_updating_wan_lan_if_list=1;
#define UNLOCK_WANLAN_IF_LIST   is_updating_wan_lan_if_list=0;
/*****************************************************************************/
/**
 *  @brief interface_add_del
 *  @param config_handler_data
 *  @return T_INT
 */
T_INT interface_add_del(struct config_handler_data *data)
{
    T_UINT32 i;
    LOCK_WANLAN_IF_LIST

    if(data->isLAN != IF_TYPE_WLAN && DEV_GET(data->interface) == NULL)
    {
        dbg_printk("Not found %s\n", data->interface);
        UNLOCK_WANLAN_IF_LIST
        return 1;
    }
    if(data->isLAN == IF_TYPE_LAN)
    {
        for(i = 0; i < MAX_LAN_IF_NUM; i++)
        {
            /* add interface for LAN port */
            if(data->interface_add_del)
            {
                if(strcmp(lan_if_names[i], data->interface) == 0)
                {
                    break;
                }
                if(strlen(lan_if_names[i]) == 0)
                {
                    strcpy(lan_if_names[i], data->interface);
                    lan_if_num++;
                    break;
                }
            }
            else    /* delete interface for LAN port */
            {
                if(strcmp(lan_if_names[i], data->interface) == 0)
                {
                    memset(&lan_if_names[i], 0x0, MAX_IFNAME_LEN);
                    if(i != (lan_if_num-1))
                    {
                        strcpy(lan_if_names[i], lan_if_names[lan_if_num-1]);
                        memset(lan_if_names[lan_if_num-1], 0x0, MAX_IFNAME_LEN);
                    }
                    lan_if_num--;
                    break;
                }
            }
        }
    }
    if(data->isLAN == IF_TYPE_WAN)
    {
        for(i = 0; i < MAX_WAN_IF_NUM; i++)
        {
            /* add interface for WAN port */
            if(data->interface_add_del)
            {
                if(strcmp(wan_if_names[i], data->interface) == 0)
                {
                    break;
                }
                if(strlen(wan_if_names[i]) == 0)
                {
                    strcpy(wan_if_names[i], data->interface);
                    wan_if_num++;
                    break;
                }
            }
            else    /* delete interface for WAN port */
            {
                if(strcmp(wan_if_names[i], data->interface) == 0)
                {
                    memset(&wan_if_names[i], 0x0, MAX_IFNAME_LEN);
                    if(i != (wan_if_num-1))
                    {
                        strcpy(lan_if_names[i], lan_if_names[wan_if_num-1]);
                        memset(lan_if_names[wan_if_num-1], 0x0, MAX_IFNAME_LEN);
                    }
                    wan_if_num--;
                    break;
                }
            }
        }
    }
    if(data->isLAN == IF_TYPE_WLAN)
    {
        for(i = 0; i < MAX_WLAN_IF_NUM; i++)
        {
            /* add interface for WLAN port */
            if(data->interface_add_del)
            {
                if(strcmp(wlan_if_names[i], data->interface) == 0)
                {
                    break;
                }
                if(strlen(wlan_if_names[i]) == 0)
                {
                    strcpy(wlan_if_names[i], data->interface);
                    wlan_if_num++;
                    break;
                }
            }
            else    /* delete interface for WLAN port */
            {
                if(strcmp(wlan_if_names[i], data->interface) == 0)
                {
                    memset(&wlan_if_names[i], 0x0, MAX_IFNAME_LEN);
                    if(i != (wlan_if_num-1))
                    {
                        strcpy(wlan_if_names[i], lan_if_names[wlan_if_num-1]);
                        memset(wlan_if_names[wlan_if_num-1], 0x0, MAX_IFNAME_LEN);
                    }
                    wlan_if_num--;
                    break;
                }
            }
        }
    }
    update_wan_lan_if_list();

    /* Unlock */
    UNLOCK_WANLAN_IF_LIST

    return 0;
}

/*****************************************************************************/
/**
 *  @brief add_mac_list
 *  @param mac_passlist
 *  @return T_INT
 */
T_INT add_mac_list(struct mac_passlist *data)
{
    T_UINT32 i;

    for(i = 0; i < MAX_MAC_PASS_TABLE; i++)
    {
        /* add MAC for interface */
        if(data->isExist)
        {
            if(!mac_pass_table[i].isExist)
            {
                strcpy(mac_pass_table[i].interface, data->interface);
                memcpy(mac_pass_table[i].dev_addr, data->dev_addr, sizeof(data->dev_addr));
                mac_pass_table[i].isExist = 1;
                mac_if_num++;
                break;
            }
        }
        else    /* delete MAC for interface */
        {
            if(strcmp(mac_pass_table[i].interface, data->interface) == 0)
            {
                if(memcmp(mac_pass_table[i].dev_addr, data->dev_addr, sizeof(data->dev_addr)))
                {
                    if(i != (mac_if_num-1))
                    {
                        memcpy(&mac_pass_table[i], &mac_pass_table[mac_if_num-1], sizeof(mac_pass_table[0]));
                        mac_pass_table[mac_if_num-1].isExist = 0;
                    }
                    mac_if_num--;
                    break;
                }
            }
        }
    }
    return 0;
}
/*****************************************************************************/

/**
 * @brief cmd_help
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_help(T_VOID* priv, cli_data* cli_data)
{
	cli_entry *pTable = (cli_entry *) priv;
	T_INT32 i = 0;

	dbg_printk("--- Available Commands ---\n");
	while(pTable[i].opMode != CMD_END_TAG)
	{
		if(cli_data != NULL)
		{
			if((pTable[i].opMode & cli_data->mode) == 0)
			{
				i++;
				continue;
			}
            dbg_printk(CLI_CMD_NAME, pTable[i].cmdName, pTable[i].description);
            if(strlen(pTable[i].usage))
            {
                dbg_printk(CLI_CMD_USAGE, pTable[i].usage);
            }
		}
        i++;
	}
    return CLI_NOTHING;
}


/*****************************************************************************/
/**
 * @brief cmd_port_vlan_id
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_port_vlan_id(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        sscanf(data, "%d,%d,%d,%d,%d,%d,%d,%d",
                &port_vlan_id_list[0], &port_vlan_id_list[1], &port_vlan_id_list[2], &port_vlan_id_list[3],
                &port_vlan_id_list[4], &port_vlan_id_list[5], &port_vlan_id_list[6], &port_vlan_id_list[7]);
        update_vlan_info();
    }
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_vlan_add
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_vlan_add(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        struct vlan_passlist vlan_data;
        sscanf(data, "%d:%s", (T_INT32 *)&vlan_data.vlan_id, vlan_data.interface);
        if(is_vlan_pass_through)
        {
            vlan_data.isExist = 1;
            add_vlan_id_list(&vlan_data);
        }
    }
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_vlan_del
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_vlan_del(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        struct vlan_passlist vlan_data;
        sscanf(data, "%d:%s", (T_INT32 *)&vlan_data.vlan_id, vlan_data.interface);
        if(is_vlan_pass_through)
        {
            vlan_data.isExist = 0;
            add_vlan_id_list(&vlan_data);
        }
    }
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_vlan_clean
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_vlan_clean(T_VOID* priv, cli_data* cli_data)
{
    memset(&vlan_pass_table, 0x0, sizeof(vlan_pass_table));
    vlan_if_num = 0;
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_vlan_pass
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_vlan_pass(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        if(strcmp(data, "on") == 0)
        {
            is_vlan_pass_through = 1;
        }
        else
        {
            is_vlan_pass_through = 0;
        }
    }
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_lan_add
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_lan_add(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        struct config_handler_data config_data;
        config_data.isLAN = IF_TYPE_LAN;
        config_data.interface_add_del = 1;
        strcpy(config_data.interface, data);
        interface_add_del(&config_data);
    }
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_lan_del
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_lan_del(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        struct config_handler_data config_data;
        config_data.isLAN = IF_TYPE_LAN;
        config_data.interface_add_del = 0;
        strcpy(config_data.interface, data);
        interface_add_del(&config_data);
    }
    return CLI_NOTHING;
}


/*****************************************************************************/
/**
 * @brief cmd_lan_ip
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_lan_ip(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        hex_to_i(data, 8, &lan_ip_address);
    }
    return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_lan_mac
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_lan_mac(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //lan_mac <mac>
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        T_UINT8 mac_addr[ETH_ALEN];
        mac_str_to_mac_bin(lan_mac_address, data);
    }
    return CLI_NOTHING;
}
#if WLAN_SUPPORT_URL_REDIRECT_VLAN
/*****************************************************************************/
/**
 * @brief cmd_lan_additional_ip
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_lan_additional_ip(T_VOID* priv, cli_data* cli_data)
{
	T_UINT32 tmp;
	T_INT32 chk = 0; 
	T_INT32 i = 0;
	
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
		if(add_ip_idx>=(ADDITIONAL_LAN_IP_NUM))
		{
			printk("add ip idx >= allow num(%d), do nothing..!!\n",ADDITIONAL_LAN_IP_NUM);
		}
		else
		{
			hex_to_i(data, 8, &tmp);
			//if addip is exist already ,do not need to add it again 
			for(i=0;i<add_ip_idx;i++)
			{
				if(add_lan_ip[i]==tmp)
				{
					chk=1;
					break;
				}
			}
			if(chk==0)
				hex_to_i(data, 8, &add_lan_ip[add_ip_idx++]);
		}
    }
    return CLI_NOTHING;
}
#endif /* WLAN_SUPPORT_URL_REDIRECT_VLAN */
/*****************************************************************************/
/**
 * @brief cmd_wan_add
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_wan_add(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        struct config_handler_data config_data;
        config_data.isLAN = IF_TYPE_WAN;
        config_data.interface_add_del = 1;
        strcpy(config_data.interface, data);
        interface_add_del(&config_data);
    }
    return CLI_NOTHING;
}


/*****************************************************************************/
/**
 * @brief cmd_wan_del
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_wan_del(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        struct config_handler_data config_data;
        config_data.isLAN = IF_TYPE_WAN;
        config_data.interface_add_del = 0;
        strcpy(config_data.interface, data);
        interface_add_del(&config_data);
    }
    return CLI_NOTHING;
}


/*****************************************************************************/
/**
 * @brief cmd_wlan_add
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_wlan_add(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        struct config_handler_data config_data;
        config_data.isLAN = IF_TYPE_WLAN;
        config_data.interface_add_del = 1;
        strcpy(config_data.interface, data);
        interface_add_del(&config_data);
    }
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_wlan_del
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_wlan_del(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        struct config_handler_data config_data;
        config_data.isLAN = IF_TYPE_WLAN;
        config_data.interface_add_del = 0;
        strcpy(config_data.interface, data);
        interface_add_del(&config_data);
    }
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_mac_add
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_mac_add(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 2)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        struct mac_passlist mac_data;
        mac_str_to_mac_bin(mac_data.dev_addr, data1);
        strcpy(mac_data.interface, data2);
        if(is_mac_pass_through)
        {
            mac_data.isExist = 1;
            add_mac_list(&mac_data);
        }
    }
    return CLI_NOTHING;
}


/*****************************************************************************/
/**
 * @brief cmd_mac_del
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_mac_del(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 2)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        struct mac_passlist mac_data;
        mac_str_to_mac_bin(mac_data.dev_addr, data1);
        strcpy(mac_data.interface, data2);
        if(is_mac_pass_through)
        {
            mac_data.isExist = 0;
            add_mac_list(&mac_data);
        }
    }
    return CLI_NOTHING;
}


/*****************************************************************************/
/**
 * @brief cmd_mac_clean
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_mac_clean(T_VOID* priv, cli_data* cli_data)
{
    memset(&mac_pass_table, 0x0, sizeof(mac_pass_table));
    mac_if_num = 0;
    return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_mac_pass
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_mac_pass(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        if(strcmp(data, "on") == 0)
        {
            is_mac_pass_through = 1;
        }
        else
        {
            is_mac_pass_through = 0;
        }
    }
    return CLI_NOTHING;
}




#if DSC_CAPTIVE_PORTAL
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_group
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_group(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal group <number>
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        if(data)
        {
            g_captive_portal_group = x_atoi(data);
        }
    }
    return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_pass
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_pass(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 1)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal ctrl on/off
		T_CHAR *data = cli_get_next_token(cli_data, 0);
		if(strcmp(data, "on") == 0)
		{
			is_captive_portal = 1;
		}
		else
		{
			is_captive_portal = 0;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_mac
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_mac(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 1)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal add_mac <mac>
		T_CHAR *data = cli_get_next_token(cli_data, 0);
		T_UINT8 mac_addr[ETH_ALEN];
		mac_str_to_mac_bin(mac_addr, data);
		memcpy(dev_mac, mac_addr, sizeof(mac_addr));
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_add_if
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_add_if(T_VOID* priv, cli_data* cli_data)
{
	int i;
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal add_if <index> <interface>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		//check if the interface exist
		for(i = 0; i < WLAN_SSID_NUM; i++)
		{
			if(strcmp(group[x_atoi(data1)].if_names[i], data2) == 0)
				return CLI_NOTHING;
		}
		for(i = 0; i < WLAN_SSID_NUM; i++)
		{
			if(strcmp(group[x_atoi(data1)].if_names[i], "") == 0)
			{
				strcpy(group[x_atoi(data1)].if_names[i], data2);
				break;
			}
		}
		if(i == WLAN_SSID_NUM) return CLI_PARAMS_ERR;
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_del_if
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_del_if(T_VOID* priv, cli_data* cli_data)
{
	int i;
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal del_if <index> <interface>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		for(i = 0; i < WLAN_SSID_NUM; i++)
		{
			if(strcmp(group[x_atoi(data1)].if_names[i], data2) == 0)
			{
				memset(group[x_atoi(data1)].if_names[i], 0x0, MAX_IFNAME_LEN);
				break;
			}
		}
		if(i == WLAN_SSID_NUM) return CLI_PARAMS_ERR;
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_del_all_if
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_del_all_if(T_VOID* priv, cli_data* cli_data)
{
	int i, j;
	//captive_portal del_all_if
	for(i = 0; i < g_captive_portal_group; i++)
	{
		for(j = 0; j < WLAN_SSID_NUM; j++)
		{
			strcpy(group[i].if_names[j], "");
		}
	}

	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_redirect_mac
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_redirect_mac(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal redirect_mac <index> <mac>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		T_UINT8 mac_addr[ETH_ALEN];
		mac_str_to_mac_bin(mac_addr, data2);
		memcpy(group[x_atoi(data1)].redirect_mac, mac_addr, sizeof(mac_addr));
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_redirect_ip
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_redirect_ip(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal redirect_ip <index> <IP address>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		group[x_atoi(data1)].redirect_ip = ip_str_to_int(data2);
	}
	return CLI_NOTHING;
}
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_external_redirect_port
 * @param t_void* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_external_redirect_port(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal external_redirect_port <index> <port>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(x_atoi(data2) > 0 && x_atoi(data2) < 65536)
		{
			group[x_atoi(data1)].external_redirect_port = x_atoi(data2);
		}
		else
		{
			return CLI_PARAMS_ERR;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_redirect_port
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_redirect_port(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal redirect_port <index> <port>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(x_atoi(data2) > 0 && x_atoi(data2) < 65536)
		{
			group[x_atoi(data1)].redirect_port = x_atoi(data2);
		}
		else
		{
			return CLI_PARAMS_ERR;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_external_redirect_sec_port
 * @param t_void* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_external_redirect_sec_port(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal external_redirect_sec_port <index> <port>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(x_atoi(data2) > 0 && x_atoi(data2) < 65536)
		{
			group[x_atoi(data1)].external_redirect_port_2 = x_atoi(data2);
		}
		else
		{
			return CLI_PARAMS_ERR;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_redirect_sec_ip
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_redirect_sec_ip(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal redirect_sec_ip <index> <IP address>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		group[x_atoi(data1)].redirect_ip_2 = ip_str_to_int(data2);
	}
	return CLI_NOTHING;
}
#else
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_redirect_https_port
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_redirect_https_port(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal redirect_https_port <index> <port>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(x_atoi(data2) > 0 && x_atoi(data2) < 65536)
		{
			group[x_atoi(data1)].redirect_https_port = x_atoi(data2);
		}
		else
		{
			return CLI_PARAMS_ERR;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_redirect_http_port
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_redirect_http_port(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal redirect_http_port <index> <port>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(x_atoi(data2) > 0 && x_atoi(data2) < 65536)
		{
			group[x_atoi(data1)].redirect_http_port = x_atoi(data2);
		}
		else
		{
			return CLI_PARAMS_ERR;
		}
	}
	return CLI_NOTHING;
}
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_social_login_ip_list_update
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_social_login_ip_list_update(T_VOID* priv, cli_data* cli_data)
{
    struct file *filePtr;
    mm_segment_t oldfs;
    loff_t pos;
    char buf;
    int i=0,z=0;
    T_CHAR  buf_temp[20]={0};
    oldfs = get_fs(); 
    set_fs(KERNEL_DS);
    filePtr = filp_open("/tmp/social_login_ip.txt", O_RDONLY, 0);

    if (IS_ERR(filePtr))
    {
        printk(KERN_ERR "### %s:%d ### file open error !\n",__FUNCTION__,__LINE__);
        return CLI_NOTHING;
    }
    else
    {
        pos = 0;
        while(vfs_read(filePtr,&buf, 1, &pos)>0)
        {
            if(buf!='\n')
            {
                buf_temp[i]=buf;
                i++;
            }
            else
            {
                sscanf(buf_temp,"0x%08x",&social_login_ip[z]);
                z++;
                i = 0;
                sprintf(buf_temp,"%s","");
            }
        }
        social_login_ip_count = z;
    }
    filp_close(filePtr,NULL);
    set_fs(oldfs);
    return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_social_login_ip_list
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_social_login_ip_list(T_VOID* priv, cli_data* cli_data)
{
    if(cli_data->argc != 2)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal social_login_ip_list <index> [on/off]
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        if(strcmp(data2, "on") == 0)
        {
            group[x_atoi(data1)].social_login_ip_list_enable = 1;
        }
        else
        {
            group[x_atoi(data1)].social_login_ip_list_enable = 0;
        }
    }
    return CLI_NOTHING;
}
#endif
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_PASSCODE
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_paypal_ip_list
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_paypal_ip_list(T_VOID* priv, cli_data* cli_data)
{
    if (cli_data->argc != 2)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal paypal_ip_list <index> [on/off]
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        if(strcmp(data2, "on") == 0)
        {
            group[x_atoi(data1)].paypal_ip_list_enable = 1;
            struct file *filePtr;
            mm_segment_t oldfs;
            loff_t pos;
            char buf;
            int i=0,z=0;
            T_CHAR  buf_temp[20]={0};
            oldfs = get_fs();
            set_fs(KERNEL_DS);
		    filePtr = filp_open("/tmp/paypal_ip.txt", O_RDONLY, 0);

            if (IS_ERR(filePtr))
            {
                printk(KERN_ERR "### %s:%d ### file open error !\n",__FUNCTION__,__LINE__);
                return CLI_NOTHING;
            }
            else
            {
                pos = 0;
                while(vfs_read(filePtr,&buf, 1, &pos)>0)
                {
                    if(buf!='\n')
                    {
                        buf_temp[i]=buf;
                        i++;
                    }
                    else
                    {
                        sscanf(buf_temp,"0x%08x",&paypal_ip[z]);
                        z++;
                        i = 0;
                        sprintf(buf_temp,"%s","");
                    }
                }
                int j =0;
                paypal_ip_count = z;
            }
            filp_close(filePtr,NULL);
            set_fs(oldfs);
        }
        else
        {
            group[x_atoi(data1)].paypal_ip_list_enable = 0;
        }
    }
    return CLI_NOTHING;
}
#endif
#if 0//WLAN_SUPPORT_URL_REDIRECT_IP_FILTER
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_ip_filter_enable
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_ip_filter_enable(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal ip_filter_enable <index> [on/off]
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(strcmp(data2, "on") == 0)
		{
            group[x_atoi(data1)].ip_filter_enable = 1;
		}
		else
		{
            group[x_atoi(data1)].ip_filter_enable = 0;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_num_ip_filter_rule
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_num_ip_filter_rule(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal num_ip_filter <index> <num>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(x_atoi(data2) > 0 && x_atoi(data2) < 65)
		{
			group[x_atoi(data1)].num_ip_filter_rule = x_atoi(data2);
		}
		else
		{
			return CLI_PARAMS_ERR;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_add_ip
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_add_ip(T_VOID* priv, cli_data* cli_data)
{
    if(4 != cli_data->argc)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal add_ip <index> <ip_index> <ip> <mask>
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        T_CHAR *data3 = cli_get_next_token(cli_data, 2);
        T_CHAR *data4 = cli_get_next_token(cli_data, 3);
        group[x_atoi(data1)].ip_list[x_atoi(data2)] = ip_str_to_int(data3);
        group[x_atoi(data1)].mask_list[x_atoi(data2)] = ip_str_to_int(data4);
    }
    return CLI_NOTHING;
}
#endif
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_input_https_port
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_input_https_port(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal input_https_port <index> <port>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(x_atoi(data2) > 0 && x_atoi(data2) < 65536)
		{
			group[x_atoi(data1)].input_https_port = x_atoi(data2);
		}
		else
		{
			return CLI_PARAMS_ERR;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_input_http_port
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_input_http_port(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal input_http_port <index> <port>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		if(x_atoi(data2) > 0 && x_atoi(data2) < 65536)
		{
			group[x_atoi(data1)].input_http_port = x_atoi(data2);
		}
		else
		{
			return CLI_PARAMS_ERR;
		}
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_mem_add_mac
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_mem_add_mac(T_VOID* priv, cli_data* cli_data)
{
	int i;
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal mem_add_mac <index> <mac>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		T_UINT8 mac_addr[ETH_ALEN];
		mac_str_to_mac_bin(mac_addr, data2);
		for(i = 0; i < MAX_USERS_NUM; i++)
		{
			if(mem[i].group_id == x_atoi(data1) && memcmp(mem[i].mac_addr, mac_addr, sizeof(mac_addr)) == 0)
			{
				break;
			}
		}
		if(i == MAX_USERS_NUM)
		{
			for(i = mem_index; i < mem_index+MAX_USERS_NUM; i++)
			{
				if(mem[i%MAX_USERS_NUM].is_auth == 0)
				{
					memcpy(mem[i%MAX_USERS_NUM].mac_addr, mac_addr, sizeof(mac_addr));
					mem[i%MAX_USERS_NUM].group_id = x_atoi(data1);
					mem_index = i%MAX_USERS_NUM+1;
					break;
				}
			}
		}
		if(i == MAX_USERS_NUM) return CLI_PARAMS_ERR;
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_mem_del_mac
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_mem_del_mac(T_VOID* priv, cli_data* cli_data)
{
	int i;
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal mem_del_mac <index> <mac>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		for(i = 0; i < MAX_USERS_NUM; i++)
		{
			T_UINT8 mac_addr[6];
			mac_str_to_mac_bin(mac_addr, data2);
			if(mem[i].group_id == x_atoi(data1) && memcmp(mem[i].mac_addr, mac_addr, sizeof(mac_addr)) == 0)
			{
				memset(mem[i].mac_addr, 0x0, sizeof(mac_addr));
				mem[i].is_auth = 0;
				mem[i].group_id = 0;
				break;
			}
		}
		if(i == MAX_USERS_NUM) return CLI_PARAMS_ERR;
	}
	return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_mem_allow
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_mem_allow(T_VOID* priv, cli_data* cli_data)
{
	int i;
	int j;
	int first_replace_idx = -1;
	unsigned char mac_null[6] = {0, 0, 0, 0, 0, 0};
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal mem_allow <index> <mac>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		T_UINT8 mac_addr[6];
		mac_str_to_mac_bin(mac_addr, data2);
		for(i = 0; i < MAX_USERS_NUM; i++)
		{
			if(mem[i].group_id == x_atoi(data1) && memcmp(mem[i].mac_addr, mac_addr, sizeof(mac_addr)) == 0)
			{
				mem[i].is_auth = 1;
				break;
			}
		}

#if DSC_EXTERNAL_CAPTIVE_PORTAL
        if(group[x_atoi(data1)].external_enable) // check external captive portal is enabled
        {
            if(i != MAX_USERS_NUM) // check the mac exist in captive portal member
            {
                for(j = 0; j < MAX_EXTERNAL_USERS_NUM; j++)
                {
                    if(external_mem[j].group_id == x_atoi(data1) && memcmp(external_mem[j].mac_addr, mac_addr, sizeof(mac_addr)) == 0)
                    {
                        external_mem[j].is_auth = 1;
                        break;
                    }
                }
            }
        }
#endif
		if(i == MAX_USERS_NUM)
#if 1
		return CLI_PARAMS_ERR;
#endif
	}
	return CLI_NOTHING;
}

#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_mem_allow_romaing
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_mem_allow_romaing(T_VOID* priv, cli_data* cli_data)
{
	int i;
	int j;
	int first_replace_idx = -1;
	unsigned char mac_null[6] = {0, 0, 0, 0, 0, 0};
	if(cli_data->argc != 3)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal mem_allow <index> <mac> <user_tId>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);		
		T_CHAR *data3 = cli_get_next_token(cli_data, 2);
		
		T_UINT8 mac_addr[6];
		mac_str_to_mac_bin(mac_addr, data2);
		for(i = 0; i < MAX_USERS_NUM; i++)
		{
			if(mem[i].group_id == x_atoi(data1) && memcmp(mem[i].mac_addr, mac_addr, sizeof(mac_addr)) == 0)
			{
				mem[i].is_auth = 1;
				break;
			}
		}

#if DSC_EXTERNAL_CAPTIVE_PORTAL
        if(group[x_atoi(data1)].external_enable) // check external captive portal is enabled
        {
            if(i != MAX_USERS_NUM) // check the mac exist in captive portal member
            {
                for(j = 0; j < MAX_EXTERNAL_USERS_NUM; j++)
                {
                    if(external_mem[j].group_id == x_atoi(data1) && memcmp(external_mem[j].mac_addr, mac_addr, sizeof(mac_addr)) == 0)
                    {
                        external_mem[j].is_auth = 1;
                        break;
                    }
                }
            }
        }
#endif
		if(i == MAX_USERS_NUM && (user[x_atoi(data3)-1].type == 0))
		{
            /* could not find mac, add it in database */
			first_replace_idx = -1;
			for(j = 0; j < MAX_USERS_NUM; j++)
			{
				if(memcmp(mem[j].mac_addr, mac_null, sizeof(mac_null)) == 0)
				{
					memcpy(mem[j].mac_addr, mac_addr, sizeof(mac_addr));
					mem[j].group_id = x_atoi(data1);
					mem[j].is_auth = 1;
					break;
				}
				if((mem[j].is_auth == 0) && (first_replace_idx == -1))
					first_replace_idx = j;
			}
            /* could not find mac, replace the no-auth mac */
			if((j == MAX_USERS_NUM) && (first_replace_idx != -1))
			{
				memcpy(mem[first_replace_idx].mac_addr, mac_addr, sizeof(mac_addr));
				mem[first_replace_idx].group_id = x_atoi(data1);
				mem[first_replace_idx].is_auth = 1;
			}
		}
	}
	return CLI_NOTHING;
}


//#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_user_mac_add
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_user_mac_add(T_VOID* priv, cli_data* cli_data)
{
	int i;
	int j;
	int first_replace_idx = -1;
	unsigned char mac_null[6] = {0, 0, 0, 0, 0, 0};
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal mem_allow <index> <mac>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);		
		T_UINT8 mac_addr[6];
		mac_str_to_mac_bin(mac_addr, data1);
		if(x_atoi(data2) >MAX_USERS_ACCOUNT_NUM)
			return CLI_PARAMS_ERR;
		memcpy(user[x_atoi(data2) - 1].mac_addr, mac_addr, sizeof(mac_addr));
	}
	return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_captive_portal_user_mac_add
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_user_mac_rm(T_VOID* priv, cli_data* cli_data)
{
	int i;
	int j;
	int first_replace_idx = -1;
	unsigned char mac_null[6] = {0, 0, 0, 0, 0, 0};
	if(cli_data->argc != 1)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		if(x_atoi(data1) >MAX_USERS_ACCOUNT_NUM)
			return CLI_PARAMS_ERR;

		if(memcmp(user[x_atoi(data1) - 1].mac_addr, mac_null, sizeof(mac_null)) != 0)
			memcpy(user[x_atoi(data1) - 1].mac_addr, mac_null, sizeof(mac_null));
	}
	return CLI_NOTHING;
}
#endif

/*****************************************************************************/
/**
 * @brief cmd_captive_portal_mem_deny
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_mem_deny(T_VOID* priv, cli_data* cli_data)
{
	int i;
#if DSC_EXTERNAL_CAPTIVE_PORTAL
	int j;
#endif
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal mem_deny <index> <mac>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		T_UINT8 mac_addr[6];
		mac_str_to_mac_bin(mac_addr, data2);
		for(i = 0; i < MAX_USERS_NUM; i++)
		{
			if(mem[i].group_id == x_atoi(data1) && memcmp(mem[i].mac_addr, mac_addr, sizeof(mac_addr)) == 0)
			{
				mem[i].is_auth = 0;
				break;
			}
		}
#if DSC_EXTERNAL_CAPTIVE_PORTAL // captive_portal_external_mem_deny
        for(j = 0; j < MAX_EXTERNAL_USERS_NUM; j++)
        {
            if(external_mem[j].group_id == x_atoi(data1) && memcmp(external_mem[j].mac_addr, mac_addr, sizeof(mac_addr)) == 0)
            {
                external_mem[j].is_auth = 0;
                break;
            }
        }
#endif
		if(i == MAX_USERS_NUM) return CLI_PARAMS_ERR;
	}
	return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_captive_portal_mem_deny_group
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_mem_deny_group(T_VOID* priv, cli_data* cli_data)
{
	int i;
	if(cli_data->argc != 1)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal mem_deny_group <index>
		T_CHAR *data = cli_get_next_token(cli_data, 0);

		for(i = 0; i < MAX_USERS_NUM; i++)
		{
			if(mem[i].group_id == x_atoi(data))
			{
				mem[i].is_auth = 0;
				break;
			}
		}
#if DSC_EXTERNAL_CAPTIVE_PORTAL // captive_portal_external_mem_deny_group
        for(i = 0; i < MAX_EXTERNAL_USERS_NUM; i++)
        {
            if(external_mem[i].group_id == x_atoi(data))
            {
                external_mem[i].is_auth = 0;
                break;
            }
        }
#endif
	}
	return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_captive_portal_mem_deny_all
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_mem_deny_all(T_VOID* priv, cli_data* cli_data)
{
	int i;
	for(i = 0; i < MAX_USERS_NUM; i++)
	{
		mem[i].is_auth = 0;
	}
#if DSC_EXTERNAL_CAPTIVE_PORTAL // captive_portal_external_mem_deny_all
    for(i = 0; i < MAX_EXTERNAL_USERS_NUM; i++)
    {
        external_mem[i].is_auth = 0;
    }
#endif
	
	return CLI_NOTHING;
}
#if DSC_EXTERNAL_CAPTIVE_PORTAL
/*****************************************************************************/
/**
 * @brief cmd_external_captive_portal_enable
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_external_captive_portal_enable(T_VOID* priv, cli_data* cli_data)
{
    if(2 != cli_data->argc)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        // external captive_portal is enable <index> <enable>
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        group[x_atoi(data1)].external_enable = x_atoi(data2);
    }
    return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_external_captive_portal_redirect_ip
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_external_captive_portal_redirect_ip(T_VOID* priv, cli_data* cli_data)
{
    if(2 != cli_data->argc)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal external redirect_ip <index> <IP address>
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        group[x_atoi(data1)].external_redirect_ip = ip_str_to_int(data2);
    }
    return CLI_NOTHING;
}
// /*****************************************************************************/
// /**
//  * @brief cmd_external_captive_portal_auth_type
//  * @param T_VOID* priv
//  * @param cli_data* cli_data
//  * @return cli_status
//  */
// cli_status cmd_external_captive_portal_auth_type(T_VOID* priv, cli_data* cli_data)
// {
//     if(2!= cli_data->argc)
//     {
//         return CLI_PARAMS_ERR;
//     }
//     else
//     {
//         //captive_portal external external_auth_type <index> <type>
//         T_CHAR *data1 = cli_get_next_token(cli_data, 0);
//         T_CHAR *data2 = cli_get_next_token(cli_data, 1);
//         strcpy(group[x_atoi(data1)].external_auth_type,data2);
//     }
//     return CLI_NOTHING;
// }
/*****************************************************************************/
/**
 * @brief cmd_external_captive_portal_auth_key
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_external_captive_portal_auth_key(T_VOID* priv, cli_data* cli_data)
{
    if(2 != cli_data->argc)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal external external_auth_key <index> <key>
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        strcpy(group[x_atoi(data1)].external_auth_key,data2);
    }
    return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_external_captive_portal_input_http_port
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_external_captive_portal_input_http_port(T_VOID* priv, cli_data* cli_data)
{
    if(2 != cli_data->argc)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal external input_http_port <index> <port>
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        if((0 < x_atoi(data2)) && (65536 > x_atoi(data2)))
        {
            group[x_atoi(data1)].external_input_http_port = x_atoi(data2);
        }
        else
        {
            return CLI_PARAMS_ERR;
        }
    }
    return CLI_NOTHING;
}
/*****************************************************************************/
/**
 * @brief cmd_external_captive_portal_input_https_port
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_external_captive_portal_input_https_port(T_VOID* priv, cli_data* cli_data)
{
    if(2 != cli_data->argc)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal external input_http_port <index> <port>
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        if((0 < x_atoi(data2)) && (65536 > x_atoi(data2)))
        {
            group[x_atoi(data1)].external_input_https_port = x_atoi(data2);
        }
        else
        {
            return CLI_PARAMS_ERR;
        }
    }
    return CLI_NOTHING;
}
#endif



#if DSC_CLOUD_EXTERNAL_CAPTIVE_PORTAL
/*****************************************************************************/
/**
 * @brief cmd_cloud_ecp_user_read
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_cloud_ecp_user_read(T_VOID* priv, cli_data* cli_data)
{   
    //captive_portal cloud_ecp_user_read
    struct file *fp; 
    mm_segment_t oldfs; 
    loff_t pos;
    char buf[16] = {0};
    int k = 0;
    char mac_str[20]={0};
    
    fp=filp_open("/tmp/cloud_ex_auth_user",O_CREAT|O_RDWR|O_SYNC,0777); 
    if (IS_ERR(fp))
        return CLI_PARAMS_ERR;
    

    oldfs=get_fs(); 
    set_fs(KERNEL_DS); 
    for(k = 0; k < MAX_EXTERNAL_USERS_NUM; k++)
    {
        if(external_mem[k].is_auth == 1 )
        {
            memset(&mac_str, 0, sizeof(mac_str));
            mac_bin_to_mac_str(mac_str, external_mem[k].mac_addr);
            sprintf(buf,"%s\n", mac_str);
            //for debug         
            printk("#############%s:%d#################buf = %s\n", __FUNCTION__, __LINE__, buf);

            pos = 0;
            //vfs_write(fp, buf, sizeof(buf), &pos);
            vfs_write(fp, buf, strlen(buf), &pos);
        }
    }
    sprintf(buf,"EOF\n");

    pos = 0;
    //vfs_write(fp, buf, sizeof(buf), &pos);
    vfs_write(fp, buf, strlen(buf), &pos);

    set_fs(oldfs); 
    filp_close(fp,NULL); 
        
    return CLI_NOTHING;
}

#if NMS_SUPPORT_CLOUD_AGENT_IN_AP_ROUTER
/*****************************************************************************/
/**
 * @brief cmd_external_captive_portal_is_router_mode
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_external_captive_portal_is_router_mode(T_VOID* priv, cli_data* cli_data)
{
    if(2 != cli_data->argc)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        // external captive_portal is enable <index> <enable>
        T_CHAR *data1 = cli_get_next_token(cli_data, 0);
        T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        group[x_atoi(data1)].external_is_router = x_atoi(data2);
    }
    return CLI_NOTHING;
}
#endif
#endif





#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
/*****************************************************************************/
/**
 * @brief cmd_captive_portal_user_max
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_user_max(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal user_max <user_tId> <value>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		
		if(x_atoi(data1) >MAX_USERS_ACCOUNT_NUM)
			return CLI_PARAMS_ERR;
		if(user[x_atoi(data1)-1].traffic_max == 0)
		{
			user[x_atoi(data1)-1].traffic_quota = x_atoi(data2)*1000;
			user[x_atoi(data1)-1].traffic_quota = user[x_atoi(data1)-1].traffic_quota * 1000;
		}
		user[x_atoi(data1)-1].traffic_max = x_atoi(data2)*1000;//*1000;
		user[x_atoi(data1)-1].traffic_max = user[x_atoi(data1)-1].traffic_max * 1000;
	}
		
	return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_captive_portal_user_quota
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_user_quota(T_VOID* priv, cli_data* cli_data)
{
	unsigned char mac_null[6] = {0, 0, 0, 0, 0, 0};
	UINT64	tmp_quota = 0;
	
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal user_quota <user_tId> <value>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		
		tmp_quota = x_atoi(data2)*1000;
		
		if(x_atoi(data1) >MAX_USERS_ACCOUNT_NUM)
			return CLI_PARAMS_ERR;

		//check
		if((memcmp(user[x_atoi(data1) - 1].mac_addr, mac_null, sizeof(mac_null)) == 0))
		{
			if((user[x_atoi(data1)-1].traffic_quota != 0) || ((user[x_atoi(data1)-1].traffic_quota == 0) && (user[x_atoi(data1)-1].traffic_max == tmp_quota*1000)))
			{
				user[x_atoi(data1)-1].traffic_quota = tmp_quota;
				user[x_atoi(data1)-1].traffic_quota = user[x_atoi(data1)-1].traffic_quota * 1000;
			}
		}
		else
		{
			if(tmp_quota*1000 < user[x_atoi(data1)-1].traffic_quota && (user[x_atoi(data1)-1].traffic_quota - (tmp_quota*1000) > 50000000))
			{
				user[x_atoi(data1)-1].traffic_quota = tmp_quota;
				user[x_atoi(data1)-1].traffic_quota = user[x_atoi(data1)-1].traffic_quota * 1000;
			}
		}
	}
		
	return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_captive_portal_user_type
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_user_type(T_VOID* priv, cli_data* cli_data)
{
	if(cli_data->argc != 2)
	{
		return CLI_PARAMS_ERR;
	}
	else
	{
		//captive_portal user_type <user_tId> <value>
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		
		if(x_atoi(data1) >MAX_USERS_ACCOUNT_NUM)
			return CLI_PARAMS_ERR;

		user[x_atoi(data1)-1].type= x_atoi(data2);  //0 or 1
	}
		
	return CLI_NOTHING;
}

/*****************************************************************************/
/**
 * @brief cmd_captive_portal_user_quota_read
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_captive_portal_user_quota_read(T_VOID* priv, cli_data* cli_data)
{	
    if (cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        //captive_portal user_quota_read <user_tId>
        struct file *fp;
        mm_segment_t oldfs;
        loff_t pos;
        char buf[16] = {0};

        T_CHAR *data1 = cli_get_next_token(cli_data, 0);

        if (x_atoi(data1) >MAX_USERS_ACCOUNT_NUM)
            return CLI_PARAMS_ERR;

        fp = filp_open("/tmp/user_quota",O_CREAT|O_RDWR|O_SYNC,0777);
        if (IS_ERR(fp))
            return CLI_PARAMS_ERR;

        if (user[x_atoi(data1)-1].traffic_quota != 0)
            sprintf(buf,"%llu\n", (user[x_atoi(data1)-1].traffic_max - user[x_atoi(data1)-1].traffic_quota));
        else
            sprintf(buf,"%llu\n", user[x_atoi(data1)-1].traffic_max);
//for debug 		
//		printk("#############%s:%d#################traffic_max = %llu\n", __FUNCTION__, __LINE__, user[x_atoi(data1)-1].traffic_max);
//		printk("#############%s:%d#################traffic_quota = %llu\n", __FUNCTION__, __LINE__, user[x_atoi(data1)-1].traffic_quota);
//		printk("#############%s:%d#################buf = %s\n", __FUNCTION__, __LINE__, buf);
        oldfs=get_fs();
        set_fs(KERNEL_DS);

        pos = 0;
        //vfs_write(fp, buf, sizeof(buf), &pos);
        vfs_write(fp, buf, strlen(buf), &pos);

        set_fs(oldfs);
        filp_close(fp,NULL);
    }

    return CLI_NOTHING;
}
#endif
#if DSC_DNS_WALLEDGARDEN
/*****************************************************************************/
cli_status cmd_captive_portal_assign_walledgarden(T_VOID* priv, cli_data* cli_data)
{
	if (cli_data->argc != 2)
    {
        return CLI_PARAMS_ERR;
    }
    else
	{
		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
        if(strcmp(data2, "-1") == 0)
        {
            group[x_atoi(data1)].walledgarden_type=0;
        }
        else if(x_atoi(data2)>=0
            && x_atoi(data2)<MAX_SUPPORT_WALLEDGARDEN_GROUP
		)
		{
			group[x_atoi(data1)].walledgarden_type |= ((UINT64)1<<(x_atoi(data2)));
		}
			
	}
	return CLI_NOTHING;
}
#endif
#endif




#if DSC_DNS_REDIRECT

/*****************************************************************************/
/**
 * @brief dsc_nbnsEncodeName
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
#define NBNS_ENCODE_H(c) ('A' + (((c) >> 4) & 0x0F))
#define NBNS_ENCODE_L(c) ('A' + ((c) & 0x0F))

size_t dsc_nbnsEncodeName(const char *src, unsigned char *dest)
{
   size_t i;
   size_t j;
   char c;

   //Point to first byte of the output buffer
   j = 0;

   //NetBIOS names are 32-byte long
   // dest[j++] = 32;

   //Parse input name
   for(i = 0; i < 15 && src[i] != '\0'; i++)
   {
      //Convert current character to uppercase
      // c = toupper((unsigned char) src[i]);
      c = (unsigned char) src[i];
      
      //Encode character
      dest[j++] = NBNS_ENCODE_H(c);
      dest[j++] = NBNS_ENCODE_L(c);
   }

   //Pad NetBIOS name with space characters
   for(; i < 15; i++)
   {
      //Encoded space character
      dest[j++] = NBNS_ENCODE_H(' ');
      dest[j++] = NBNS_ENCODE_L(' ');
   }

   //The 16th character is the NetBIOS suffix
   dest[j++] = NBNS_ENCODE_H(0);
   dest[j++] = NBNS_ENCODE_L(0);

   //Terminate the NetBIOS name with a zero length count
   dest[j++] = 0;

   //Return the length of the encoded NetBIOS name
   return j;
}
/*****************************************************************************/
/**
 * @brief cmd_dns_redirect_ctrl
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_dns_redirect_ctrl(T_VOID* priv, cli_data* cli_data)
{
    int i;
    char name[32+1];

    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        if(strcmp(data, "on")==0)
        {
            dns_redirect=1;
        }
        else
        {
            dns_redirect=0;
        }

    }
    return CLI_NOTHING;
}
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
/*****************************************************************************/
/**
 * @brief cmd_dns_redirect_add_multiple_domain_name
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_dns_redirect_add_multiple_domain_name(T_VOID* priv, cli_data* cli_data)
{
    int i;
    char name[64+1];

    if(!(cli_data->argc ==2))
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
		T_CHAR *data2 = cli_get_next_token(cli_data, 1);
		int index = x_atoi(data2);
        strcpy(dns_domain_name[index], data);
        memset(name, 0, sizeof(name));
        strcpy(name, dns_domain_name[index]);
        
        /* netbios name */
        for(i=0; i<strlen(dns_domain_name[index]); i++)
        {
            /* toupper */
            if (dns_domain_name[index][i] >= 'a' && dns_domain_name[index][i] <= 'z') 
            {
                name[i] = dns_domain_name[index][i] - 'a' + 'A'; 
            }
            /* domain -> netbios name */
            dsc_nbnsEncodeName(name, netbios_name[index]);
        }
    }
    return CLI_NOTHING;
}
#else
/*****************************************************************************/
/**
 * @brief cmd_dns_redirect_add_domain_name
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_dns_redirect_add_domain_name(T_VOID* priv, cli_data* cli_data)
{
    int i;
    char name[32+1];

    if(cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {
        T_CHAR *data = cli_get_next_token(cli_data, 0);
        strcpy(dns_domain_name, data);
        
        memset(name, 0, sizeof(name));
        strcpy(name, dns_domain_name);
        
        /* netbios name */
        for(i=0; i<strlen(dns_domain_name); i++)
        {
            /* toupper */
            if (dns_domain_name[i] >= 'a' && dns_domain_name[i] <= 'z') 
            {
                name[i] = dns_domain_name[i] - 'a' + 'A'; 
            }
            /* domain -> netbios name */
            dsc_nbnsEncodeName(name, netbios_name);
        }
    }
    return CLI_NOTHING;
}
#endif
#endif


#if DSC_DNS_WALLEDGARDEN
/*****************************************************************************/
T_VOID update_wgHashTbl(T_CHAR* name,T_INT g)
{	
	int i,chk=0;
	for(i=0;i<wg_hashtbl.cnt;i++)
	{
		if (strcmp(name,wg_hashtbl.name[i])==0)
			chk=i+1;
	}
	if(!chk)
	{
		wg_hashtbl.name[wg_hashtbl.cnt] = name;
		wg_hashtbl.gmask[wg_hashtbl.cnt] |= ((UINT64)1 << g);
		wg_hashtbl.cnt++;
	}
	else
	{
		wg_hashtbl.gmask[chk-1] |= ((UINT64)1 << g);
	}
		
}
/*****************************************************************************/
T_VOID set_walledgarden_domain(T_INT g)
{
	T_CHAR  buf_temp[64+1]={0};
	T_CHAR	file_path[64+1]={0};
	T_CHAR buf;
	struct file *filePtr;
	mm_segment_t oldfs;
	loff_t pos;
	T_INT i=0,z=0;
	oldfs = get_fs();
	memset(&walled_garden[g].wg_hdomain, 0, sizeof(walled_garden[g].wg_hdomain));
	sprintf(file_path,"/tmp/WalledGardenDomain%d.txt",g);
	set_fs(KERNEL_DS);
	filePtr = filp_open(file_path, O_RDONLY, 0);

	if (IS_ERR(filePtr))
	{
		printk(KERN_ERR "### %s:%d ### file[%s] open error !\n",__FUNCTION__,__LINE__,file_path);
		return;
	}
	else
	{
		pos=0;
		while(vfs_read(filePtr,&buf, 1, &pos)>0)
		{
			if(buf!='\n')
			{
				buf_temp[i]=buf;
				i++;
			}
			else
			if(strlen(buf_temp))
			{
				sscanf(buf_temp,"%s",walled_garden[g].wg_hdomain.name[z]);
				update_wgHashTbl(walled_garden[g].wg_hdomain.name[z],g);
				z++;
				//printk("%s\n",buf_temp);
				i = 0;
				memset(buf_temp,0,sizeof(buf_temp));
			}
		}
		walled_garden[g].wg_hdomain.cnt = z;
	}
	filp_close(filePtr,NULL);
	set_fs(oldfs);
	return;
}
/*****************************************************************************/
T_VOID set_walledgarden_net(T_INT g)
{
	T_CHAR  buf_temp[32+1]={0};
	T_CHAR	file_path[64+1]={0};
	T_CHAR buf;
	struct file *filePtr;
	mm_segment_t oldfs;
	loff_t pos;
	T_INT i=0,z=0;
	oldfs = get_fs();
	memset(&walled_garden[g].wg_net, 0, sizeof(walled_garden[g].wg_net));
	sprintf(file_path,"/tmp/WalledGardenNet%d.txt",g);
	set_fs(KERNEL_DS);
	filePtr = filp_open(file_path, O_RDONLY, 0);

	if (IS_ERR(filePtr))
	{
		printk(KERN_ERR "### %s:%d ### file[%s] open error !\n",__FUNCTION__,__LINE__,file_path);
		return;
	}
	else
	{
		pos=0;
		while(vfs_read(filePtr,&buf, 1, &pos)>0)
		{
			if(buf!='\n')
			{
				buf_temp[i]=buf;
				i++;
			}
			else 
			if(strlen(buf_temp))
			{
				sscanf(buf_temp,"0x%08x/0x%08x",&walled_garden[g].wg_net.ip[z],&walled_garden[g].wg_net.mask[z]);
				z++;
				//printk("%s\n",buf_temp);
				i = 0;
				memset(buf_temp,0,sizeof(buf_temp));
			}
		}
		walled_garden[g].wg_net.cnt = z;
	}
	filp_close(filePtr,NULL);
	set_fs(oldfs);
	return;
}
/*****************************************************************************/
cli_status cmd_add_walledgarden(T_VOID* priv, cli_data* cli_data)
{
    if (cli_data->argc != 1)
    {
        return CLI_PARAMS_ERR;
    }
    else
    {

		T_CHAR *data1 = cli_get_next_token(cli_data, 0);
		T_INT g=0;
		if(strcmp(data1, "-1") == 0)
        {
			memset(&walled_garden, 0, sizeof(walled_garden)); 
			memset(&wg_hashtbl, 0, sizeof(wg_hashtbl)); 
			for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
			{	
				spin_lock_init(&walled_garden[g].wg_hip.lock);
			}
        }
        else if(x_atoi(data1)>=0
				&&x_atoi(data1)<MAX_SUPPORT_WALLEDGARDEN_GROUP)
        {	
			g=x_atoi(data1);
			set_walledgarden_domain(g);
			set_walledgarden_net(g);
			if(walled_garden[g].wg_hdomain.cnt||walled_garden[g].wg_net.cnt)
				walled_garden[g].wg_en=1;	
        }

    }
    return CLI_NOTHING;
}
#endif
/*****************************************************************************/
/**
 * @brief Default all global variables in this module
 * @param T_VOID* priv
 * @param cli_data* cli_data
 * @return cli_status
 */
cli_status cmd_default(T_VOID* priv, cli_data* cli_data)
{
    // Must sync all global default value
    is_pppoe_pass_through=0;
    is_ipv6_paas_through=0;
    is_mcast_pkt_pass_through=0;
    is_mcast_trans_reverse = 0;
    is_mac_pass_through=0;
    is_vlan_pass_through=0;
    is_wan_mac_cloned=0;
    is_updating_wan_lan_if_list=0;
    vlan_id=0;
#if DSC_CAPTIVE_PORTAL
    is_captive_portal=0;
    memset(&group, 0, sizeof(group));
    memset(&mem, 0, sizeof(mem));
    mem_index=0;
    memset(&dev_mac, 0, sizeof(dev_mac));
#if DSC_EXTERNAL_CAPTIVE_PORTAL
    memset(&external_mem, 0, sizeof(external_mem));
    external_mem_index=0;
#endif
#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
    memset(&user, 0, sizeof(user));
#endif
#endif

#if DSC_DNS_REDIRECT
    memset(&dns_domain_name, 0, sizeof(dns_domain_name));
    memset(&netbios_name, 0, sizeof(netbios_name));
#endif




    lan_ip_address=0;

    memset(&port_vlan_id_list, 0, sizeof(port_vlan_id_list));

    memset(&wan_if_names, 0, sizeof(wan_if_names));
    memset(&lan_if_names, 0, sizeof(lan_if_names));
    memset(&wlan_if_names, 0, sizeof(wlan_if_names));

    wan_if_num=0;
    lan_if_num=0;
    wlan_if_num=0;
    mac_if_num=0;
    vlan_if_num=0;

    memset(&lan_if_list, 0, sizeof(lan_if_list));
    memset(&wan_if_list, 0, sizeof(wan_if_list));
    memset(&wlan_if_list, 0, sizeof(wlan_if_list));
    ssid2If = NULL;
    eth_lan_if = NULL;
    memset(&mac_pass_table, 0, sizeof(mac_pass_table));
    memset(&vlan_pass_table, 0, sizeof(vlan_pass_table));
    memset(&vlan_if_info, 0, sizeof(vlan_if_info));

#if DSC_DNS_WALLEDGARDEN
	int g;
	memset(&walled_garden, 0, sizeof(walled_garden));
	memset(&wg_hashtbl, 0, sizeof(wg_hashtbl)); 
	for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
	{	
		spin_lock_init(&walled_garden[g].wg_hip.lock);
	}
#endif

    return CLI_NOTHING;
}
