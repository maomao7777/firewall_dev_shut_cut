/** 
 *   @file dsc_config.c
 *   @brief dsc config file
 *   @author cfho
 *   @version 0.1
 *   @date  2012-04-05
 *   @bug none
 *   @warning none
*/
/** -------------------------------------------------------------------------
                          INCLUDE HEADER FILES                             
  -------------------------------------------------------------------------*/

// #define DO_PRINTK 1
#include <gconfig.h>
#include <dsc_main.h>
#include <dsc_config.h>
#include <dsc_cmd.h>
#if DSC_RECORD_CLIENT_REQ
#include <record_client_req.h>
#endif
#if DSC_DNS_WALLEDGARDEN
#include <dsc_walledgarden_handler.h>
#endif

#if DSC_ETH_IGMP_SNOOPING
#include "igmp_mld_snooping.h"
extern igmp_snooping_allow_list_t g_igmp_snooping_allow_list[MAX_SNOOP_ALLOW_ENTRY_NUM];
UINT32 is_igmp_snooping_enable=0;
#endif



#if 1
#define DEV_GET(x) __dev_get_by_name(&init_net,x)
#endif

/*
 *  global variables
 */
UINT32 is_pppoe_pass_through=0;
UINT32 is_ipv6_paas_through=0;
UINT32 is_mcast_pkt_pass_through=0;
UINT32 is_mcast_trans_reverse = 0;
UINT32 is_mac_pass_through=0;
UINT32 is_vlan_pass_through=0;
UINT32 is_wan_mac_cloned=0;
UINT32 is_updating_wan_lan_if_list=0;
UINT32 vlan_id=0;


#if DSC_CAPTIVE_PORTAL
UINT32 is_captive_portal=0;
struct captive_portal_group_info group[MAX_CAPTIVE_PORTAL_GROUP];
UINT32 g_captive_portal_group=MAX_CAPTIVE_PORTAL_GROUP;
struct mem_info mem[MAX_USERS_NUM];
UINT32 mem_index=0;
UINT8 dev_mac[ETH_ALEN];
#if DSC_EXTERNAL_CAPTIVE_PORTAL
struct external_mem_info external_mem[MAX_EXTERNAL_USERS_NUM];
T_UINT32 external_mem_index=0;
#endif
#if DSC_CAPTIVE_PORTAL_TRAFFIC_LIMITATION
struct user_info user[MAX_USERS_ACCOUNT_NUM];
#endif
#endif

#if WLAN_SUPPORT_URL_REDIRECT_WITH_SOCIAL_LOGIN || NMS_SUPPORT_CAPTIVE_PORTAL_SOCIAL_LOGIN
extern T_UINT32 social_login_ip[SOCIAL_LOGIN_DOMAIN_NUMBER+16]; //FB known ip is num of 16
extern T_INT social_login_ip_count;
#endif

#if DSC_DNS_REDIRECT
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
int dns_redirect=0;
char dns_domain_name[DNS_RED_SUPPORT_DOMAIN_NUM][64+1];
char netbios_name[DNS_RED_SUPPORT_DOMAIN_NUM][64+1];
#else
int dns_redirect=0;
char dns_domain_name[32+1];
char netbios_name[64+1];
#endif
#endif

UINT32 lan_ip_address=0;
UINT8 lan_mac_address[ETH_ALEN];
#if WLAN_SUPPORT_URL_REDIRECT_VLAN
T_UINT32 add_lan_ip[ADDITIONAL_LAN_IP_NUM]={0};
T_UINT8  add_ip_idx = 0;
#endif
 
UINT32 port_vlan_id_list[MAX_PORT_NUM];

 
/** Packet path:  Ethernet wired --> Eth2 --> Eth2.1 --> Br0,
    so we should add the eth2.1, eth2.2, ra0, ra1, rather than br0 adn eth2 */
UINT8  wan_if_names[MAX_WAN_IF_NUM][MAX_IFNAME_LEN];
UINT8  lan_if_names[MAX_LAN_IF_NUM][MAX_IFNAME_LEN];
UINT8  wlan_if_names[MAX_WLAN_IF_NUM][MAX_IFNAME_LEN];
UINT32 wan_if_num=0;
UINT32 lan_if_num=0;
UINT32 wlan_if_num=0;
UINT32 mac_if_num=0;
UINT32 vlan_if_num=0;

struct net_device *lan_if_list[MAX_LAN_IF_NUM];
struct net_device *wan_if_list[MAX_WAN_IF_NUM];
struct net_device *wlan_if_list[MAX_WLAN_IF_NUM];
struct net_device *ssid2If;
struct net_device *eth_lan_if;
struct mac_passlist mac_pass_table[MAX_MAC_PASS_TABLE];
struct vlan_passlist vlan_pass_table[MAX_VLAN_PASS_TABLE];
struct vlan_if_info  vlan_if_info[MAX_VLAN_ID];
#define LOCK_WANLAN_IF_LIST     is_updating_wan_lan_if_list=1;
#define UNLOCK_WANLAN_IF_LIST   is_updating_wan_lan_if_list=0;
#define PROC_ENTRY                "dsc_config"
const char MODULE_NAME[]={"dsc"};
struct proc_dir_entry *switch_dir, *status_file;


#define IP_PATTERN               "%d.%d.%d.%d"
T_CHAR* ip_int_to_str(const T_UINT32 ip)
{
        static T_CHAR null_value[24];

        sprintf(null_value,IP_PATTERN,
                        (ip>>24)&0xff,
                        (ip>>16)&0xff,
                        (ip>>8)&0xff,
                        (ip)&0xff);

        return null_value;
}
T_UINT32 ip_str_to_int(T_CHAR *ipaddr_str)
{
        T_UINT32 reg0, reg1, reg2, reg3;
        T_UINT32 ip;

        if(!ipaddr_str || ipaddr_str[0] == '\0')
        {
            //T_PRINTF("Error! [%s] ipaddr_str is null\n", __FUNCTION__);
            return 0;
        }

        if(sscanf(ipaddr_str,IP_PATTERN, &reg3, &reg2, &reg1, &reg0) != 4)
        {
            //T_PRINTF("Error! [%s] Invalid IP address!\n", __FUNCTION__);
            return 0;
        }

        ip = (reg3<<24) + (reg2<<16) + (reg1<<8) + reg0;
        return(ip);
}

#define dbg_printk(x...) //printk(x)


#ifdef HAS_NOFITY_INTERFACE
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
static int dsc_device_event(struct notifier_block *, unsigned long, void *);

static struct notifier_block dsc_notifier_block = {
    .notifier_call = dsc_device_event,
};
/*****************************************************************************/
/**
*  @brief dsc_device_event
*  @param struct notifier_block *unused
*  @param unsigned long event
*  @param T_VOID *ptr
*  @return T_INT
*/
static T_INT dsc_device_event(struct notifier_block *unused, unsigned long event, T_VOID *ptr)
{
    struct net_device *dev = (struct net_device *)(ptr);
 
    /** we skip the local interface */
    if(strncmp(dev->name, "lo", 2) == 0)
        return NOTIFY_DONE;

    switch(event)
    {
    case NETDEV_GOING_DOWN:
    case NETDEV_DOWN:
        dbg_printk("NETDEV_DOWN: down %s(%p)\n", dev->name, dev);
        update_wan_lan_if_list();
        break;
    case NETDEV_UP:
    case NETDEV_CHANGEADDR:
        dbg_printk("NETDEV_UP: up %s(%p)\n", dev->name, dev);
        update_wan_lan_if_list();
        break;
    }

    return NOTIFY_DONE;
}
#endif
#endif

/*****************************************************************************/
/**
*  @brief dsc_proc_output
*  @param T_CHAR *
*  @return T_INT
*/
static T_INT dsc_proc_output(T_CHAR *buf)
{
    char *p;
    int i,j;


    p = buf;
    p += sprintf(p, "LAN %d: ",lan_if_num);
    for(i=0;i<lan_if_num;i++)
    p += sprintf(p, "%s ",lan_if_names[i]);
    p += sprintf(p, " \n");
    p += sprintf(p, "WAN %d: ",wan_if_num);
    for(i=0;i<wan_if_num;i++)
    p += sprintf(p, "%s ",wan_if_names[i]);
    p += sprintf(p, " \n");
    p += sprintf(p, "WLAN %d: ",wlan_if_num);
    for(i=0;i<wlan_if_num;i++)
    p += sprintf(p, "%s[%s] ",wlan_if_names[i],(wlan_if_list[i]==NULL)?"Down":"Up");
    p += sprintf(p, " \n");

    p += sprintf(p, "PPPOE: %s \n",(is_pppoe_pass_through==1) ? "Enable" : "Disable");
    p += sprintf(p, "IPv6: %s \n",(is_ipv6_paas_through==1)  ? "Enable" : "Disable");
    p += sprintf(p, "Multicast Passthrough: %s \n",(is_mcast_pkt_pass_through==1)  ? "Enable" : "Disable");
    p += sprintf(p, "Multicast convert reverse: %s \n",(is_mcast_trans_reverse==1)  ? "Enable" : "Disable");
    p += sprintf(p, "LAN MAC: %02X:%02X:%02X:%02X:%02X:%02X \n",
                 lan_mac_address[0]&0xff,
                 lan_mac_address[1]&0xff,
                 lan_mac_address[2]&0xff,
                 lan_mac_address[3]&0xff,
                 lan_mac_address[4]&0xff,
                 lan_mac_address[5]&0xff);
    p += sprintf(p, "LAN IP: %x \n", lan_ip_address);
    p += sprintf(p, "MAC Passthrough: %s \n",(is_mac_pass_through==1) ? "Enable" : "Disable");
    if(is_mac_pass_through)
    {
        p += sprintf(p, "----------------------------\n"); 
        p += sprintf(p, "MAC               IF  \n");
        for(i=0;i<MAX_MAC_PASS_TABLE;i++)
        {
            if(mac_pass_table[i].isExist == 0)
                break;
            p += sprintf(p, "%02X:%02X:%02X:%02X:%02X:%02X ",mac_pass_table[i].dev_addr[0]&0xff,mac_pass_table[i].dev_addr[1]&0xff,mac_pass_table[i].dev_addr[2]&0xff,mac_pass_table[i].dev_addr[3]&0xff,mac_pass_table[i].dev_addr[4]&0xff,mac_pass_table[i].dev_addr[5]&0xff);
            p += sprintf(p, "%s ",mac_pass_table[i].interface);
            p += sprintf(p, "\n");
        }
        p += sprintf(p, "----------------------------\n");
    }
    p += sprintf(p, "VLAN PassThrough: %s \n",(is_vlan_pass_through==1) ? "Enable" : "Disable");

#if 1
    p += sprintf(p, "---------------%s \n","");
    for(i=0;i<MAX_VLAN_ID;i++)/*0 means router mode*/
    {
        if(vlan_if_info[i].num_of_interface==0)
            continue;
        for(j=0;j<vlan_if_info[i].num_of_interface;j++)
        {
            p += sprintf(p, "VID_%d[%d]-->member[%s] \n",i,vlan_if_info[i].num_of_interface,
                         vlan_if_info[i].dev[j]->name);
        }
    }
#endif

#if DSC_CAPTIVE_PORTAL
	p += sprintf(p, "Captive Portal enable: %d\n", is_captive_portal);
	p += sprintf(p, "Dev mac: [%02X:%02X:%02X:%02X:%02X:%02X]\n",
					dev_mac[0] & 0xFF,
					dev_mac[1] & 0xFF,
					dev_mac[2] & 0xFF,
					dev_mac[3] & 0xFF,
					dev_mac[4] & 0xFF,
					dev_mac[5] & 0xFF);
    if (is_captive_portal)
	for(i = 0; i < g_captive_portal_group; i++)
	{
		p += sprintf(p, "[Captive Portal group info] %d\n", i);
		p += sprintf(p, "Control interface:\t");
		for(j = 0; j < WLAN_SSID_NUM; j++)
		{
			if(strcmp(group[i].if_names[j], "") != 0)
			{
				p += sprintf(p, "%s", group[i].if_names[j]);
			}
		}
		p += sprintf(p, "\n");
        if (!group[i].input_http_port && !group[i].input_https_port) continue;
		p += sprintf(p, "Redirect mac: [%02X:%02X:%02X:%02X:%02X:%02X]\n",
					group[i].redirect_mac[0] & 0xFF,
					group[i].redirect_mac[1] & 0xFF,
					group[i].redirect_mac[2] & 0xFF,
					group[i].redirect_mac[3] & 0xFF,
					group[i].redirect_mac[4] & 0xFF,
					group[i].redirect_mac[5] & 0xFF);
		p += sprintf(p, "Redirect IP: %s\n", ip_int_to_str(group[i].redirect_ip));
		p += sprintf(p, "Input HTTP port: %d\n", group[i].input_http_port);
		p += sprintf(p, "Input HTTPS port: %d\n", group[i].input_https_port);
#if WLAN_SUPPORT_URL_REDIRECT_WITH_EXTERNAL_CAPTIVE_PORTAL
		p += sprintf(p, "External Redirect port: %d\n", group[i].external_redirect_port);
		p += sprintf(p, "Redirect port: %d\n", group[i].redirect_port);
#else
		p += sprintf(p, "Redirect HTTP port: %d\n", group[i].redirect_http_port);
		p += sprintf(p, "Redirect HTTPS port: %d\n", group[i].redirect_https_port);
#endif
#if DSC_EXTERNAL_CAPTIVE_PORTAL
        p += sprintf(p, "External Captive Portal: %s\n", (1 == group[i].external_enable) ? "Enable" : "Disable");
        if(1 == group[i].external_enable)
        {
            p += sprintf(p, "External redirect IP: %s\n", ip_int_to_str(group[i].external_redirect_ip));
//             p += sprintf(p, "External authentication type: %s\n", group[i].external_auth_type);
            p += sprintf(p, "External authentication key: %s\n", group[i].external_auth_key);
        }
        p += sprintf(p, "External input HTTP port: %d\n", group[i].external_input_http_port);
        p += sprintf(p, "External input HTTPS port: %d\n", group[i].external_input_https_port);
#endif
#if DSC_DNS_WALLEDGARDEN
		int g,cnt=0;
		p += sprintf(p, "Support walled garden group:");
		for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
		{
			if(((UINT64)1 << g) & group[i].walledgarden_type)
			{
				p += sprintf(p,cnt==0?" %d":", %d",g);
				cnt++;
			}
		}
		p += sprintf(p,"\n");		
#endif
	}
#endif

#if DSC_DNS_REDIRECT
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
	p += sprintf(p, "---------------%s \n","");
    p += sprintf(p, "[DNS redirect] DNS Domain: [%s] \n", (dns_redirect==1) ?  "Enable" : "Disable");
    p += sprintf(p, "---Name List---%s \n","");
	for(i=0; i<DNS_RED_SUPPORT_DOMAIN_NUM; i++){
		p += sprintf(p, "[DNS redirect]\n");
		p += sprintf(p, "  DNS Domain Name %d: [%s] \n",i,dns_domain_name[i]);
		p += sprintf(p, "  Netbios Name %d: [%s] \n",i,netbios_name[i]);
		p += sprintf(p, "%s",(i+1==DNS_RED_SUPPORT_DOMAIN_NUM) ? "":"--------------- \n");
	}
#else
	p += sprintf(p, "---------------%s \n","");
    p += sprintf(p, "[DNS redirect] DNS Domain: [%s] \n", (dns_redirect==1) ?  "Enable" : "Disable");
	p += sprintf(p, "[DNS redirect] DNS Domain Name: [%s] \n", dns_domain_name);
	p += sprintf(p, "[DNS redirect] Netbios Name: [%s] \n", netbios_name);
#endif
#endif
    return(p - buf);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)  
/*****************************************************************************/
/**
*  @brief dsc_read_proc
*  @return T_INT
*/

#if DSC_CAPTIVE_PORTAL
#if DSC_DNS_REDIRECT_MULTI_DOMAIN
#define MAX_MSG_SIZE	(4096+2048) //byte
#else
#define MAX_MSG_SIZE	4096
#endif
#else
#define MAX_MSG_SIZE	1024//byte
#endif
static int dsc_read_proc(struct seq_file *m, void *v)
{
      int len = 0;
      T_CHAR *msg=kmalloc(MAX_MSG_SIZE, GFP_KERNEL);
      if (!msg)
      {
            printk("Not enough memory %d.\n",MAX_MSG_SIZE);
            return 0;
      }
      len = dsc_proc_output(msg);
      if(len >= MAX_MSG_SIZE)
      {
		printk("msg size %d over %d, please check!!\n",len,MAX_MSG_SIZE);
        kfree(msg);
		return 0;
      }
        seq_printf(m, "%s\n",msg);
        kfree(msg);
      return 0;
}

static int _seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, dsc_read_proc, NULL);
}
#else
/*****************************************************************************/
/**
*  @brief dsc_read_proc
*  @return T_INT
*/
static T_INT dsc_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = dsc_proc_output(page);

    if(len <= (off + count))
    {
        *eof = 1;
    }

    *start = page + off;
    len -= off;

    if(len > count)
    {
        len = count;
    }
    if(len < 0)
    {
        len = 0;
    }
    return(len);

}
#endif

/*****************************************************************************/
/**
*  @brief dsc_write_proc
*  @return T_INT
*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) 
static T_INT dsc_write_proc(struct file *file,
       const char *user_buffer,
       unsigned long count, 
       void *data)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)
static T_INT dsc_write_proc(struct file *file,
	const char *user_buffer,
	size_t count,
	loff_t *data)
#else
static ssize_t dsc_write_proc(struct file *file, const char __user *user_buffer,
			            	size_t count, loff_t *data)
#endif
{
    T_CHAR buf[256] = {0};
    if(count < 1)
    {
        return -EINVAL;
    }
    copy_from_user(buf, &user_buffer[0], count);
    cli_handle(buf);
    return count;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)  
#else
struct file_operations dsc_fops=
{
    .open=_seq_open,
    .read= seq_read,
    .write=dsc_write_proc,
#if CFG_FOR_CUSTOMER_DLINK_TW 
	.llseek= seq_lseek,
    .release= single_release,
#endif
    .owner=THIS_MODULE,
};
#endif
/*****************************************************************************/
/**
*  @brief create_dsc_proc
*  @param T_VOID
*  @return T_INT
*/
#define LINUX_VERSION_CODE 4
static T_INT create_dsc_proc(T_VOID)
{
    int rv = 0;

    /* create directory */
    switch_dir = proc_mkdir(MODULE_NAME, NULL);
    if(switch_dir == NULL)
        return rv;

#if LINUX_VERSION_CODE < 3
    switch_dir->owner = THIS_MODULE;
#endif

#if LINUX_VERSION_CODE < 4    
    status_file = create_proc_entry(PROC_ENTRY, 0644, switch_dir);
    if(status_file == NULL)
    {
        remove_proc_entry(MODULE_NAME, NULL);
        return rv;
    }
    status_file->read_proc  = dsc_read_proc;
    status_file->write_proc = dsc_write_proc;
#else
   status_file = proc_create(PROC_ENTRY, 0644, switch_dir, &dsc_fops);
   if (status_file == NULL) {
#if 1
	proc_remove(switch_dir);
#else
	remove_proc_entry(MODULE_NAME, NULL);
#endif
      return rv;
    }
#endif    


    return rv;
}

/*****************************************************************************/
/**
*  @brief dsc_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT dsc_init_driver(T_VOID)
{
    /* Set below values for testing */
    is_pppoe_pass_through=0;
    is_ipv6_paas_through=0;
    is_mcast_pkt_pass_through=0;
    is_mcast_trans_reverse = 0;
    is_mac_pass_through=0;
    /* Init the WAN & LAN IF list */
    is_updating_wan_lan_if_list=0;
    update_wan_lan_if_list();
    dbg_printk("Start %s\n", __FUNCTION__);

    if( create_dsc_proc() != 0)
    {
        printk("error creating proc enteries for surf_status\n");
    }
    return 0;
}
 
/*****************************************************************************/
/**
*  @brief dsc_cleanup_driver
*  @param T_VOID
*  @return T_VOID
*/
T_VOID dsc_cleanup_driver(T_VOID)
{
    dbg_printk("Clean up driver %s\n", __FUNCTION__);
	remove_proc_entry(PROC_ENTRY, switch_dir);
    remove_proc_entry(MODULE_NAME, NULL);

}
/** ***********************  END  ********************************************/

