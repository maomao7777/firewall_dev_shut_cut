#ifndef _DSC_WALLEDGARDEN_HANDLER_H
#define _DSC_WALLEDGARDEN_HANDLER_H
#if 1
#define MAX_SUPPORT_WALLEDGARDEN_GROUP (20)//allssid google fb wifi4eu paypal
#define MAX_RECORD_ANS_IP 10
#define MAX_WALLEDGARDEN_HOST_DOMAIN_NAME    32
#define MAX_WALLEDGARDEN_HOST_IP MAX_WALLEDGARDEN_HOST_DOMAIN_NAME*3
#define MAX_WALLEDGARDEN_NET 20
struct wgHostDomain
{
	T_CHAR name[MAX_WALLEDGARDEN_HOST_DOMAIN_NAME][64+1];
	T_INT cnt;
};
struct wgHostIp
{
	T_UINT32 ip[MAX_WALLEDGARDEN_HOST_IP];
	T_INT cnt;
	spinlock_t lock;
};
struct wgNet
{
	T_UINT32 ip[MAX_WALLEDGARDEN_NET];
	T_UINT32 mask[MAX_WALLEDGARDEN_NET];
	T_INT cnt;
};
struct walledgarden
{
	T_INT wg_en;
	struct wgHostDomain wg_hdomain;
	struct wgHostIp wg_hip;
	struct wgNet wg_net;
};
// struct wgHash
// {
// 	T_CHAR *name;
//     unsigned long gmask;
// };
struct wgHashTbl
{
	//struct wgHash hash[MAX_WALLEDGARDEN_HOST_DOMAIN_NAME*MAX_SUPPORT_WALLEDGARDEN_GROUP];
	T_CHAR *name[MAX_WALLEDGARDEN_HOST_DOMAIN_NAME*MAX_SUPPORT_WALLEDGARDEN_GROUP];
    UINT64 gmask[MAX_WALLEDGARDEN_HOST_DOMAIN_NAME*MAX_SUPPORT_WALLEDGARDEN_GROUP];
	T_INT cnt;
};
int add_walledgarden_HostIp(unsigned int addip,struct walledgarden *wg);
int que_walledgarden_HostIp(unsigned int queip,struct walledgarden *wg);
int check_walledgarden_HostIp(unsigned int chkip,struct walledgarden *wg);
int check_walledgarden_Net(unsigned int chkip,struct walledgarden *wg);
#endif
int  dsc_walledgarden_init_driver(void);
int  dsc_walledgarden_l2_init_driver(void);
void dsc_walledgarden_cleanup_driver(void);
void dsc_walledgarden_l2_cleanup_driver(void);
int  dsc_walledgarden_rx_handler(struct sk_buff *skb);
int  dsc_walledgarden_l2_tx_handler(struct sk_buff *skb);
#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif
