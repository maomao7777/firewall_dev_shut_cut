#ifndef _DNS_REDIRECT_HANDLER_H
#define _DNS_REDIRECT_HANDLER_H

int  dns_redirect_l2_handler_init_driver(void);
void dns_redirect_l2_handler_cleanup_driver(void);
int  dns_redirect_l2_rx_handler(struct sk_buff *skb);
int  dns_redirect_l2_tx_handler(struct sk_buff *skb);

int  dns_redirect_l3_handler_init_driver(void);
void dns_redirect_l3_handler_cleanup_driver(void);
int  dns_redirect_l3_rx_handler(struct sk_buff *skb);
int  dns_redirect_l3_tx_handler(struct sk_buff *skb);

#define DOMAIN_NAME_LEN   (256+1) //512
#define NETBIOS_NAME_LEN   16

#define T_A      1  //Ipv4 address
#define T_NS     2  //Nameserver
#define T_CNAME  5  // canonical name
#define T_SOA    6  // start of authority zone
#define T_PTR    12 // domain name pointer
#define T_MX     15 //Mail server

#define DNS_PORT     53
#define NETBIOS_PORT 137
#define LLMNR_PORT   5355

typedef enum {
    MATCH_DOMAIN_ERROR = -1,
    MATCH_DOMAIN_NAME = 0
} DNS_PACKET_TYPE;

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char name[DOMAIN_NAME_LEN];
    struct R_DATA *resource;
    unsigned char rdata[DOMAIN_NAME_LEN];
};

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#endif /* _DNS_REDIRECT_HANDLER_H */
