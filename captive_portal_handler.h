#ifndef _CAPTIVE_PORTAL_HANDLER_H
#define _CAPTIVE_PORTAL_HANDLER_H

int  captive_portal_handler_init_driver(void);
void captive_portal_handler_cleanup_driver(void);
int  captive_portal_rx_handler(struct sk_buff *skb);
#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif
