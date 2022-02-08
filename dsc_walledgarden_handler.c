/**
 *   @date  2015-0521
 *   @bug none
 *   @warning none
*/
/** -------------------------------------------------------------------------
                          INCLUDE HEADER FILES
  -------------------------------------------------------------------------*/
#include <dsc_main.h>
#include <dsc_config.h>
#include <dsc_debug.h>
#include <dns_redirect_handler.h>
#include <dsc_walledgarden_handler.h>

/** -------------------------------------------------------------------------
                          DEFINITIONS
  -------------------------------------------------------------------------*/
#if CFG_ELX_DSC_DEBUG
#define dbg_printk(x...) printk(x)
#else
#define dbg_printk(x...)
#endif
#define HASH_DBG 0
/** -------------------------------------------------------------------------
                          VARIABLES
  -------------------------------------------------------------------------*/
 
/** -------------------------------------------------------------------------
                          FUNCTIONS
  -------------------------------------------------------------------------*/
#pragma pack(push, 1)
struct _r_data
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
struct _ans_record
{
	int ip_num;
    unsigned int ans_ip[MAX_RECORD_ANS_IP];
};
#if 1
struct walledgarden walled_garden[MAX_SUPPORT_WALLEDGARDEN_GROUP];
struct wgHashTbl wg_hashtbl;
#endif

/** -------------------------------------------------------------------------
                          VARIABLES
  -------------------------------------------------------------------------*/

/** -------------------------------------------------------------------------
                          FUNCTIONS
  -------------------------------------------------------------------------*/
/*****************************************************************************/
int check_walledgarden_HostIp(unsigned int chkip,struct walledgarden * wg)
{
	int cnt,chk=0;
	spin_lock(&(wg->wg_hip.lock));		
	for(cnt=0;cnt<wg->wg_hip.cnt;cnt++){
		if(wg->wg_hip.ip[cnt]==chkip){
			chk=1;
			break;
		}
	}
	spin_unlock(&(wg->wg_hip.lock));
	return chk;
}
/*****************************************************************************/
int que_walledgarden_HostIp(unsigned int queip,struct walledgarden * wg)
{
	int cnt;
	spin_lock(&(wg->wg_hip.lock));
	if(wg->wg_hip.cnt < MAX_WALLEDGARDEN_HOST_IP)
	{
		wg->wg_hip.ip[wg->wg_hip.cnt]=queip;
		wg->wg_hip.cnt++;
	}
	else
	{
		for(cnt=0;cnt<MAX_WALLEDGARDEN_HOST_IP-1;cnt++)
		{
			wg->wg_hip.ip[cnt]=wg->wg_hip.ip[cnt+1];
		}
		wg->wg_hip.ip[MAX_WALLEDGARDEN_HOST_IP-1]=queip;
	}
	spin_unlock(&(wg->wg_hip.lock));
	return 1;
}
/*****************************************************************************/
int add_walledgarden_HostIp(unsigned int addip,struct walledgarden * wg)
{
	if(check_walledgarden_HostIp(addip,wg))
		return 0;
	else
		que_walledgarden_HostIp(addip,wg);
	return 1;
}
/*****************************************************************************/
int check_walledgarden_Net(unsigned int chkip,struct walledgarden * wg)
{
	int cnt,chk=0;
	for(cnt=0;cnt<wg->wg_net.cnt;cnt++){
		if(wg->wg_net.mask[cnt])
		{
			if((wg->wg_net.ip[cnt] & wg->wg_net.mask[cnt])==(chkip & wg->wg_net.mask[cnt]))
				chk=1;
			break;
		}
	}
	return chk;
}

/*****************************************************************************/
u_char* dns_readname(unsigned char* reader,unsigned char* buffer,int* count)
{
    static unsigned char name[64+1]={0};
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 =0xc000
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}
/*****************************************************************************/
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}
/*****************************************************************************/
void DumpHex(const void* data, size_t size,const char* name) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	printk("%s:\n",name);
	for (i = 0; i < size; ++i) {
		printk("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printk(" ");
			if ((i+1) % 16 == 0) {
				printk("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printk(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printk("   ");
				}
				printk("|  %s \n", ascii);
			}
		}
	}
}

/*****************************************************************************/
/**
*  @brief 
*  @param struct 
*  @return 
*/
int dns_name_answer_check(unsigned char *data, int size, char *dname, struct _ans_record * ans)
{
    // memcpy(skb->data, dns_response, sizeof(dns_response));

    static unsigned char buf[2048],*reader;
	
    int i , n , stop, h_size; // , s;
    int cnt = 0;

    //struct sockaddr_in a;
	static struct _r_data* ans_res; //the replies resource from the DNS server
    // struct sockaddr_in dest;
    struct DNS_HEADER *dns = NULL;
    // struct QUESTION *qinfo = NULL;
    // char *name;
    

//     dbg_printk("%s[%d], size = %d\n", __FUNCTION__, __LINE__, size);

    if(size > 1600)
    {
        dbg_printk("%s[%d], wrong packet size = %d > 1600\n", __FUNCTION__, __LINE__, size);
        return 0;
    }

    // memcpy(buf, (skb->data+MAC_HEADER_LEN+IP_HEADER_LEN+UDP_HEADER_LEN), 256);
    memcpy(buf, data, size);
 
    //Set the DNS structure to standard ans
    dns = (struct DNS_HEADER *)&buf;

//     printk("\nThe response contains : ");
//     printk("\n %d Questions.",ntohs(dns->q_count));
//     printk("\n %d Answers.",ntohs(dns->ans_count));
//     printk("\n %d Authoritative Servers.",ntohs(dns->auth_count));
//     printk("\n %d Additional records.\n\n",ntohs(dns->add_count));

	if(ntohs(dns->auth_count)!=0)
		return 0;
	if(ntohs(dns->add_count)!=0)
		return 0;
	h_size=sizeof(struct DNS_HEADER);
	reader = &buf[h_size];

    //Start reading answers
    stop=0;

	
		

        n = strlen(dname);
		
        if(n && (strncasecmp(dns_readname(reader,buf,&stop), dname, n) == 0))
        {	
			//unsigned char dname_dnstype[200];
			//ChangetoDnsNameFormat(dname_dnstype,dname);
			
            //printk("%s[%d], response query name  [%s]\n", __FUNCTION__, __LINE__, dname);
			//printk("%d Answers.\n",ntohs(dns->ans_count));
			//printk("sizeall:%d\n",size);
			//printk("sizeall-h_size:%d\n",size-h_size);

			//DumpHex(&buf[h_size],size-h_size,"DNS_ALL-HEADER");

			reader+=(stop+sizeof(struct QUESTION));
			for(i=0;i<ntohs(dns->ans_count);i++)
			{
				if(cnt==MAX_RECORD_ANS_IP)
					break;
				reader+=2;// jump name discription
				ans_res = (struct _r_data*)(reader);
				//printk("ans[%d]->type :[%x],len[%x],class:[%x]\n",i+1,ntohs(ans_res->type),ntohs(ans_res->data_len),ntohs(ans_res->_class));
				if(ntohs(ans_res->type)==1
					&&ntohs(ans_res->data_len)==4
					&&ntohs(ans_res->_class)==1)
				{	
					void* p=NULL;
					reader+= sizeof(struct _r_data);
					p=reader;
					ans->ans_ip[cnt]=ntohl(*(unsigned int *)p);
					//printk("check %s ip = 0x%08x\n",dname,ntohl(*(unsigned int *)p));
					cnt++;
					reader+=ntohs(ans_res->data_len);
				}
				else
				{
					reader+= sizeof(struct _r_data)+ntohs(ans_res->data_len);
				}
				
			}
			ans->ip_num=cnt;
        }

    return cnt;
}

/*****************************************************************************/
/**
*  @brief traffic_report_rx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT dsc_walledgarden_rx_handler(struct sk_buff *skb)
{
	return STATUS_DSC_OK;
}
/*****************************************************************************/
/**
*  @brief traffic_report_rx_handler
*  @param struct sk_buff *skb
*  @return T_INT
*/
T_INT dsc_walledgarden_l2_tx_handler(struct sk_buff *skb)
{
    unsigned char *data = skb->data;
    struct ethhdr *eth_header = (struct ethhdr *)data;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
	struct _ans_record  ans={0};
    unsigned short src_port=0, dst_port=0;
    unsigned char *pdns;
    


    /*dbg_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    dbg_printk("%s[%d], %s\n", __FUNCTION__, __LINE__, skb->dev->name);
    dbg_printk("%s[%d], %x\n", __FUNCTION__, __LINE__, eth_header->h_proto);//
    dbg_printk("%s[%d], %x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__, eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2], eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
    dbg_printk("%s[%d], %x:%x:%x:%x:%x:%x\n", __FUNCTION__, __LINE__, eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2], eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);
    */
    if(eth_header->h_proto == htons(ETH_P_IP))
    {
        ip_header = (struct iphdr*)(data+ETH_HLEN);

        // dbg_printk("%s[%d], ip_header->daddr = %x\n", __FUNCTION__, __LINE__, ip_header->daddr);
        // dbg_printk("%s[%d], ip_header->saddr = %x\n", __FUNCTION__, __LINE__, ip_header->saddr);
        // dbg_printk("%s[%d], ip_header->protocol = %x\n", __FUNCTION__, __LINE__, ip_header->protocol);
        if(ip_header->protocol == IPPROTO_UDP)
        {
            udp_header= (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl);
            src_port = htons((unsigned short int) udp_header->source);
            dst_port = htons((unsigned short int) udp_header->dest);
            // dbg_printk("%s[%d], src_port= %d, dst_port=%d\n", __FUNCTION__, __LINE__, src_port, dst_port);
            pdns = (unsigned char *)udp_header;
            pdns += sizeof(struct udphdr);

                
            if(src_port == DNS_PORT)
            {
				//printk("txudpdns\n");
				int i,g,k;
#if 0
				for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
				{
					if(walled_garden[g].wg_hdomain.cnt
						&&walled_garden[g].wg_en)
					{
						for(k=0;k<walled_garden[g].wg_hdomain.cnt;k++)
						{
							if(dns_name_answer_check(pdns, htons(udp_header->len), walled_garden[g].wg_hdomain.name[k],&ans))
							{
								for(i=0;i<ans.ip_num;i++)
								{
									////printk("%s ip[%d] is 0x%08x\n",walled_garden[g].wg_hdomain.name[k],i,ans.ans_ip[i]);
									add_walledgarden_HostIp(ans.ans_ip[i],&walled_garden[g]);
								}	
							}	
						}
					}
				}
#else //check  name in hashtbl instead of every name in group
				for(i=0;i<wg_hashtbl.cnt;i++)
				{
					if (dns_name_answer_check(pdns, htons(udp_header->len),wg_hashtbl.name[i],&ans))
					{
						for(k=0;k<ans.ip_num;k++)
						{
							for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
							{
								if(walled_garden[g].wg_en
									&&walled_garden[g].wg_hdomain.cnt)
								{	
									if(wg_hashtbl.gmask[i] & ((UINT64)1 << g))
										add_walledgarden_HostIp(ans.ans_ip[k],&walled_garden[g]);
								}
							}
						}
					}
				}
#endif
            }
        }
    }

    return STATUS_DSC_OK;
}
#if 1
static T_INT walledgarden_proc_output(T_CHAR *buf)
{
    char *p;
	int i,g;
	p = buf;
	for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
	{
		if(walled_garden[g].wg_en)
		{
			p += sprintf(p,"--------------------------------\n");
			p += sprintf(p,"walledgarden group %d enable:%d \n",g,walled_garden[g].wg_en);
			p += sprintf(p,"have %d walledgarden  HostDomain list:\n",walled_garden[g].wg_hdomain.cnt);
			for(i=0;i<walled_garden[g].wg_hdomain.cnt;i++){
				if(walled_garden[g].wg_hdomain.name[i])
				{
					p += sprintf(p,"%s\n",walled_garden[g].wg_hdomain.name[i]);
				}
			}
			p += sprintf(p,"have %d walledgarden HostIp list:\n",walled_garden[g].wg_hip.cnt);
			spin_lock(&walled_garden[g].wg_hip.lock);
			for(i=0;i<walled_garden[g].wg_hip.cnt;i++){
				if(walled_garden[g].wg_hip.ip[i])
				{
					p += sprintf(p,"0x%08x\n",walled_garden[g].wg_hip.ip[i]);
				}
			}
			spin_unlock(&walled_garden[g].wg_hip.lock);
			p += sprintf(p,"have %d walledgarden Net list:\n",walled_garden[g].wg_net.cnt);
			for(i=0;i<walled_garden[g].wg_net.cnt;i++){
				if(walled_garden[g].wg_net.ip[i]&&walled_garden[g].wg_net.mask[i])
				{
					p += sprintf(p,"0x%08x/0x%08x\n",walled_garden[g].wg_net.ip[i],walled_garden[g].wg_net.mask[i]);
				}
			}
		}
		
	}
	p += sprintf(p,"--------------------------------\n");
#if HASH_DBG
	p += sprintf(p,"dbg_hashtbl cnt [%d]:\n",wg_hashtbl.cnt);
	for(i=0;i<wg_hashtbl.cnt;i++)
	{
		if(wg_hashtbl.name[i])
			p += sprintf(p,"name:%s, group:",wg_hashtbl.name[i]);
		for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
		{

			if(((UINT64)1 << g) & wg_hashtbl.gmask[i])
			
				{
					p += sprintf(p," %d",g);
				}
		}
		p += sprintf(p,"\n");
	}
#endif
	return(p - buf);
}
#define MAX_GROUP_MSG_SIZE (10*MAX_WALLEDGARDEN_HOST_IP+64*MAX_WALLEDGARDEN_HOST_DOMAIN_NAME+21*MAX_WALLEDGARDEN_NET+200)
static int dsc_read_walledgarden_proc(struct seq_file *m, void *v)
{
	  T_CHAR *msg;
      int len = 0;
	  int g,max_size=64;
	  for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
	  {
		  if(walled_garden[g].wg_en)
			  max_size+=MAX_GROUP_MSG_SIZE;
	  }
#if HASH_DBG
	  max_size+=80*wg_hashtbl.cnt;
#endif
      msg=kmalloc(max_size, GFP_KERNEL);
      if (!msg)
      {
            printk("Not enough memory %d.\n",max_size);
            return 0;
      }
      len = walledgarden_proc_output(msg);
      if(len >= max_size)
      {
		printk("msg size %d over %d, please check!!\n",len,max_size);
        kfree(msg);
		return 0;
      }
        seq_printf(m, "%s\n",msg);
        kfree(msg);
      return 0;
}
static int _status_wg_open(struct inode *inode, struct file *file)
{
	return single_open(file, dsc_read_walledgarden_proc, NULL);
}
struct file_operations walledgarden_fops=
{
    .open=_status_wg_open,
    .read= seq_read,
	.llseek= seq_lseek,
    .release= single_release
};
static T_INT create_walledgarden_proc(T_VOID)
{
    proc_create(PROC_DNS_WALLEDGARDEN, 0644, NULL, &walledgarden_fops);
    return 0;
}
#endif
/*****************************************************************************/
/**
*  @brief clt_dns_req_tmp_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT dsc_walledgarden_init_driver(T_VOID)
{
    dbg_printk("Start %s\n", __FUNCTION__);
	if(create_walledgarden_proc() != 0)
    {
        printk("error creating proc dsc/walled_garden\n");
    }
    else
	{
		int g;
		memset(walled_garden, 0, sizeof(struct walledgarden)*MAX_SUPPORT_WALLEDGARDEN_GROUP);
		memset(&wg_hashtbl, 0, sizeof(wg_hashtbl)); 
		for(g=0;g<MAX_SUPPORT_WALLEDGARDEN_GROUP;g++)
		{	
			spin_lock_init(&walled_garden[g].wg_hip.lock);
		}
	}
    return 0;
}

/*****************************************************************************/
/**
*  @brief clt_dns_req_tmp_cleanup_driver
*  @param T_VOID
*  @return T_VOID
*/
T_VOID dsc_walledgarden_cleanup_driver(T_VOID)
{
    dbg_printk("Clean up %s\n", __FUNCTION__);
	remove_proc_entry(PROC_DNS_WALLEDGARDEN, NULL);
}
/*****************************************************************************/
/**
*  @brief clt_dns_req_tmp_l2_init_driver
*  @param T_VOID
*  @return T_INT
*/
T_INT dsc_walledgarden_l2_init_driver(T_VOID)
{
    dbg_printk("Start %s\n", __FUNCTION__);

    return 0;
}
/*****************************************************************************/
/**
*  @brief clt_dns_req_tmp_l2_cleanup_driver
*  @param T_VOID
*  @return T_VOID
*/
T_VOID dsc_walledgarden_l2_cleanup_driver(T_VOID)
{
    dbg_printk("Clean up %s\n", __FUNCTION__);
}
/** ***********************  END  ********************************************/