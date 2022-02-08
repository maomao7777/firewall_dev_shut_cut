#ifndef _CAPTIVE_PORTAL_L2_HANDLER_H
#define _CAPTIVE_PORTAL_L2_HANDLER_H

int  captive_portal_l2_handler_init_driver(void);
void captive_portal_l2_handler_cleanup_driver(void);
int  captive_portal_l2_rx_handler(struct sk_buff *skb);
int  captive_portal_l2_tx_handler(struct sk_buff *skb);
#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif
