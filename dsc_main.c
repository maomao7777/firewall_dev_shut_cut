/** 
 *   @file dsc.c
 *   @brief Device Short Cut
 *   @author cfho
 *   @version 0.1
 *   @date  2012-04-04
 *   @bug none
 *   @warning none
*/
/** -------------------------------------------------------------------------
                          INCLUDE HEADER FILES                             
  -------------------------------------------------------------------------*/
#include <gconfig.h>
#include <dsc_main.h>
#include <dsc_config.h>

#if CFG_ELX_DSC_CAPTIVE_PORTAL
#include <captive_portal_handler.h>
#include <captive_portal_l2_handler.h>
#endif
#if CFG_ELX_DSC_DNS_REDIRECT
#include <dns_redirect_handler.h>
#endif
#if CFG_ELX_DSC_DNS_WALLEDGARDEN
#include <dsc_walledgarden_handler.h>
#endif

// #if DSC_SAMPLE_HANDLER
// #include <sample_handler.h>
// #endif

/** -------------------------------------------------------------------------
                          DEFINITIONS                             
  -------------------------------------------------------------------------*/

#define dbg_printk(x...) // printk(x)

/** -------------------------------------------------------------------------
                          VARIABLES                             
  -------------------------------------------------------------------------*/

/** extern function pointer from dev.c of kernel 3.2 */
extern int (*dsc_l2_handle_rx_driver)(struct sk_buff *skb);
extern int (*dsc_l2_handle_tx_driver)(struct sk_buff *skb);
extern int (*dsc_l3_handle_rx_driver)(struct sk_buff *skb);
extern int (*dsc_l3_handle_tx_driver)(struct sk_buff *skb);
static int dsc_init=0;
 

struct dsc_process
{
    int  (*init)(void);
    void (*cleanup)(void);
    int  (*rx_handle)(struct sk_buff *skb);
    int  (*tx_handle)(struct sk_buff *skb);
};

struct dsc_process dsc_l2_handler_list[]=
{
#if CFG_ELX_DSC_CAPTIVE_PORTAL
    {captive_portal_l2_handler_init_driver, captive_portal_l2_handler_cleanup_driver, captive_portal_l2_rx_handler, captive_portal_l2_tx_handler},
#endif
#if CFG_ELX_DSC_DNS_REDIRECT
    {dns_redirect_l2_handler_init_driver, dns_redirect_l2_handler_cleanup_driver, 0, dns_redirect_l2_tx_handler},
#endif
#if CFG_ELX_DSC_DNS_WALLEDGARDEN
	{dsc_walledgarden_l2_init_driver, dsc_walledgarden_l2_cleanup_driver, 0, dsc_walledgarden_l2_tx_handler},
#endif

// #if DSC_SAMPLE_HANDLER
//     {sample_l2_handler_init_driver, sample_l2_handler_cleanup_driver, sample_l2_rx_handler, sample_l2_tx_handler},
// #endif

};

struct dsc_process dsc_l3_handler_list[]=
{
    {dsc_init_driver, dsc_cleanup_driver, 0, 0},
#if CFG_ELX_DSC_CAPTIVE_PORTAL
	{captive_portal_handler_init_driver, captive_portal_handler_cleanup_driver, captive_portal_rx_handler, 0},
#endif
#if CFG_ELX_DSC_DNS_REDIRECT
    {dns_redirect_l3_handler_init_driver, dns_redirect_l3_handler_cleanup_driver, dns_redirect_l3_rx_handler, 0},
#endif
#if CFG_ELX_DSC_DNS_WALLEDGARDEN
	{dsc_walledgarden_init_driver, dsc_walledgarden_cleanup_driver, dsc_walledgarden_rx_handler, 0},
#endif
// #if DSC_SAMPLE_HANDLER
// 	{sample_handler_l3_init_driver, sample_handler_l3_cleanup_driver, sample_l3_rx_handler, sample_l3_tx_handler},
// #endif
};

/*****************************************************************************/
/**
*  @brief __dsc_l2_handle_rx_driver
*  @param struct sk_buff *skb
*  @return int
*/
int __dsc_l2_handle_rx_driver(struct sk_buff *skb)
{
    int i, status=0;

    if(0==dsc_init)
		return 0;

    dbg_printk("Start %s\n", __FUNCTION__);

    for(i=0; i<T_NUM_OF_ELEMENTS(dsc_l2_handler_list); i++)
    {
        if(dsc_l2_handler_list[i].rx_handle)
        {
            status |= dsc_l2_handler_list[i].rx_handle(skb);

            if(status & STATUS_DSC_DROP) break;
        }
    }
    return status;
}
/*****************************************************************************/
/**
*  @brief __dsc_l3_handle_rx_driver
*  @param struct sk_buff *skb
*  @return int
*/
int __dsc_l3_handle_rx_driver(struct sk_buff *skb)
{
    int i, status=0;
      
    if(0==dsc_init)
          return 0;
        
    dbg_printk("Start %s\n", __FUNCTION__);
      
    for(i=0; i<T_NUM_OF_ELEMENTS(dsc_l3_handler_list); i++)
    {
        if(dsc_l3_handler_list[i].rx_handle)
        {
            status |= dsc_l3_handler_list[i].rx_handle(skb);

            if(status & STATUS_DSC_DROP) break;
        }
    }
    
    return status;
}

/*****************************************************************************/
/**
*  @brief __dsc_l2_handle_tx_driver
*  @param struct sk_buff *skb
*  @return int
*/
int __dsc_l2_handle_tx_driver(struct sk_buff *skb)
{
    int i, status=0;

    if(0==dsc_init)
		return 0;

    dbg_printk("Start %s\n", __FUNCTION__);

    for(i=0; i<T_NUM_OF_ELEMENTS(dsc_l2_handler_list); i++)
    {
        if(dsc_l2_handler_list[i].tx_handle)
        {
            status |= dsc_l2_handler_list[i].tx_handle(skb);

            if(status & STATUS_DSC_DROP) break;
        }
    }
    return status;
}

/*****************************************************************************/
/**
*  @brief __dsc_l3_handle_tx_driver
*  @param struct sk_buff *skb
*  @return int
*/
int __dsc_l3_handle_tx_driver(struct sk_buff *skb)
{
    int i, status=0;

    if(0==dsc_init)
		return 0;

    dbg_printk("Start %s\n", __FUNCTION__);

    for(i=0; i<T_NUM_OF_ELEMENTS(dsc_l3_handler_list); i++)
    {
        if(dsc_l3_handler_list[i].tx_handle)
        {
            status |= dsc_l3_handler_list[i].tx_handle(skb);

            if(status & STATUS_DSC_DROP) break;
        }
    }
    return status;
}

/*****************************************************************************/
/**
*  @brief dsc_handler_init_driver
*  @param void
*  @return int
*/
static int __init dsc_handler_init_driver(void)
{
    int i;
      
    dbg_printk("Start %s\n", __FUNCTION__);

    for(i=0; i<T_NUM_OF_ELEMENTS(dsc_l2_handler_list); i++)
    {
        if(dsc_l2_handler_list[i].init)
            dsc_l2_handler_list[i].init();
    }
    for(i=0; i<T_NUM_OF_ELEMENTS(dsc_l3_handler_list); i++)
    {
        if(dsc_l3_handler_list[i].init)
            dsc_l3_handler_list[i].init();
    }
    dsc_init = 1;

    dsc_l2_handle_rx_driver = __dsc_l2_handle_rx_driver;
    dsc_l2_handle_tx_driver = __dsc_l2_handle_tx_driver;
    dsc_l3_handle_rx_driver = __dsc_l3_handle_rx_driver;
    dsc_l3_handle_tx_driver = __dsc_l3_handle_tx_driver;
    
    return 0;
}
 
/*****************************************************************************/
/**
*  @brief dsc_handler_cleanup_driver
*  @param void
*  @return void
*/
static void __exit dsc_handler_cleanup_driver(void)
{
    int i;

    dbg_printk("Stop %s\n", __FUNCTION__);

	dsc_l2_handle_rx_driver = 0;
    dsc_l2_handle_tx_driver = 0;
    dsc_l3_handle_rx_driver = 0;
    dsc_l3_handle_tx_driver = 0;

    dsc_init = 0;

    for(i=0; i<T_NUM_OF_ELEMENTS(dsc_l2_handler_list); i++)
    {
        if(dsc_l2_handler_list[i].cleanup)
            dsc_l2_handler_list[i].cleanup();
    }
	for(i=0; i<T_NUM_OF_ELEMENTS(dsc_l3_handler_list); i++)
    {
        if(dsc_l3_handler_list[i].cleanup)
            dsc_l3_handler_list[i].cleanup();
    }
}

module_init(dsc_handler_init_driver);
module_exit(dsc_handler_cleanup_driver);
/** ***********************  END  ********************************************/