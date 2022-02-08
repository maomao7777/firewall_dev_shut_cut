#ifndef _SAMPLE_HANDLER_H
#define _SAMPLE_HANDLER_H

int  sample_l2_handler_init_driver(void);
void sample_l2_handler_cleanup_driver(void);
int  sample_l2_rx_handler(struct sk_buff *skb);
int  sample_l2_tx_handler(struct sk_buff *skb);

int  sample_handler_l3_init_driver(void);
void sample_handler_l3_cleanup_driver(void);
int  sample_l3_rx_handler(struct sk_buff *skb);
int  sample_l3_tx_handler(struct sk_buff *skb);

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif /* _SAMPLE_HANDLER_H */
