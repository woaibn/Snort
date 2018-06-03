/*
这段程序用于接收alert_sock套接字的报警消息，并转发给控制器。
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>//for close
#include <fcntl.h> // for open
#include <stdint.h>//
#include <arpa/inet.h>//
#include <netinet/in.h>  //
#include <string.h>//
#include <time.h>
#include <sys/time.h>

#define UNSOCK_FILE "snort_alert" //套接字文件名称。
#define ALERTMSG_LENGTH 256  //报警信息长度。

/*
 * Ethernet header
 * MAC 地址 
 */
typedef struct _EtherHdr
{
    uint8_t ether_dst[6];   //目的MAC
    uint8_t ether_src[6];   //源MAC
    uint16_t ether_type;    //以太网类型

} EtherHdr;

/*
 * IP地址数据结构
 */
typedef struct _IPHdr
{
    uint8_t ip_verhl;      /* 版本       version & header length */
    uint8_t ip_tos;        /* 服务类型   type of service */
    uint16_t ip_len;       /* 数据报长度 datagram length */
    uint16_t ip_id;        /* 标识       identification  */
    uint16_t ip_off;       /* 段偏移     fragment offset */
    uint8_t ip_ttl;        /* 生存时间   time to live field */
    uint8_t ip_proto;      /* 协议类型   datagram protocol */
    uint16_t ip_csum;      /* 校验和     checksum */
    struct in_addr ip_src; /* 源IP地址   source IP */
    struct in_addr ip_dst; /* 目的IP地址 dest IP */
} IPHdr;

/* 系统警报的时间是格林威治时间，不是北京时间。
 * we must use fixed size of 32 bits, because on-disk
 * format of savefiles uses 32-bit tv_sec (and tv_usec)
 * 我们必须使用固定大小的32位，因为SaveFixes的磁盘格式使用32位TVIESEC（和TVIUSEC）。
 * 但32位二进制表示时间容易溢出导致异常（）。
 * 此类系统的Unix时间戳最多可以使用到格林威治时间2038年01月19日03时14分07秒
 *（二进制：01111111 11111111 11111111 11111111）。其后一秒，二进制数字会
 * 变为10000000 00000000 00000000 00000000，
 * 发生溢出错误，造成系统将时间误解为1901年12月13日20时45分52秒。
 */
struct sf_timeval32
{
    uint32_t tv_sec;      /* seconds */
    uint32_t tv_usec;     /* microseconds */
};

/*
以下是用于转换时间格式。
unix时间戳，定义为格林威治时间1970年1月1日00分00秒起至现在的总秒数。
结构struct timeval，它精确到微妙。
在头文件<time.h>中定义。
struct timeval {
	long    tv_sec;         ///< seconds 秒
	long    tv_usec;        ///< microseconds 微秒
};

typedef int32_t time_t;
或 typedef long time_t; 
time_t是一种时间类型，一般用来存放自1970年1月1日0点0时0分开始的秒数。

直接存储年月日的是一个结构：
struct tm
{
    int tm_sec;  //秒，正常范围0-59， 但允许至61
    int tm_min;  //分钟，0-59
    int tm_hour; //小时， 0-23
    int tm_mday; //日，即一个月中的第几天，1-31/
    int tm_mon;  //月， 从一月算起，0-11  1+p->tm_mon;
    int tm_year;  //年， 从1900至今已经多少年  1900＋ p->tm_year;
    int tm_wday; //星期，一周中的第几天， 从星期日算起，0-6
    int tm_yday; //从今年1月1日到目前的天数，范围0-365
    int tm_isdst; //日光节约时间的旗标
};
*/


/*
 * 定义事件 Event 的数据结构。
 * 这些值是在 log.c中赋给的。
 */
#if defined(FEAT_OPEN_APPID)
#define MAX_EVENT_APPNAME_LEN  64
#endif /* defined(FEAT_OPEN_APPID) */
typedef struct _Event
{
    uint32_t sig_generator;   /* snort哪一部分生成alert。  which part of snort generated the alert? */
    uint32_t sig_id;          /* sig id for this generator */
    uint32_t sig_rev;         /* sig revision for this id */
    uint32_t classification;  /* event classification */
    uint32_t priority;        /* event priority */
    uint32_t event_id;        /* event ID */
    uint32_t event_reference; /* reference to other events that have gone off,
                                * such as in the case of tagged packets...
                                */
    struct sf_timeval32 ref_time;   /* 指向。reference time for the event reference */

#if defined(FEAT_OPEN_APPID)
    char     app_name[MAX_EVENT_APPNAME_LEN];
#endif /* defined(FEAT_OPEN_APPID) */
    /* Don't add to this structure because this is the serialized data
     * struct for unified logging.
     */
} Event;

#if 0
typedef struct _EventID
{
    uint32_t sequence;
    uint32_t seconds;
} EventID;

typedef struct _Event
{
    EventID id;
    uint32_t uSeconds;
    SigInfo sigInfo;
} Event;

#endif


/* alert packet 定义报警数据包的数据结构 。
 *this is equivalent to the pcap pkthdr struct, but we need
 * a 32 bit one for unified output
 */
struct pcap_pkthdr32
{
    struct sf_timeval32 ts;   /* 包的时间戳 packet timestamp */
    uint32_t caplen;          /* 包的总长度 packet capture length */
    uint32_t len;             /* 包的有效长度 packet "real" length */
};

//位置：src/output-plugins文件夹下spo_alert_unixsock.h
//套接字输出插件所输出的信息： 一个 alert警报数据包。
typedef struct _Alertpkt
{
    uint8_t alertmsg[ALERTMSG_LENGTH]; /* 警报信息variable.. */
    struct pcap_pkthdr32 pkth;//这是pcap抓到的数据包的时间、长度信息。
    uint32_t dlthdr;       /* 数据链路层（MAC）头偏移量。 datalink header offset. (ethernet, etc.. ) */
    uint32_t nethdr;       /* 网络（IP）头偏移量。network header offset. (ip etc...) */
    uint32_t transhdr;     /* 传输协议偏移量。transport header offset (tcp/udp/icmp ..) */
    uint32_t data;  //数据包静载荷。
    uint32_t val;  /* 哪个字段有效。which fields are valid. (NULL could be
                    * valids also) */
    /* Packet struct --> was null */
#define NOPACKET_STRUCT 0x1  //0x表示16进制。
    /* no transport headers in packet */
#define NO_TRANSHDR    0x2
    uint8_t pkt[65535];//数据包。被检测到的数据包中的原始数据 packet。
    Event event;//snort生成的报警事件。
} Alertpkt;


/*
 * 传输层协议地址数据结构。
 */
typedef struct _TCPHdr
{
    uint16_t th_sport;     /* source port */
    uint16_t th_dport;     /* destination port */
    uint32_t th_seq;       /* sequence number */
    uint32_t th_ack;       /* acknowledgement number */
    uint8_t th_offx2;      /* offset and reserved */
    uint8_t th_flags;
    uint16_t th_win;       /* window */
    uint16_t th_sum;       /* checksum */
    uint16_t th_urp;       /* urgent pointer */

}TCPHdr;
#ifdef _MSC_VER
  /* Visual C++ pragma to enable warning messages
   * about nonstandard bit field type
   */
  #pragma warning( default : 4214 )
#endif


typedef struct _UDPHdr
{
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_len;
    uint16_t uh_chk;

}UDPHdr;


typedef struct _ICMPHdr
{
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    union
    {
        struct
        {
            uint8_t pptr;
            uint8_t pres1;
            uint16_t pres2;
        } param;

        struct in_addr gwaddr;

        struct idseq
        {
            uint16_t id;
            uint16_t seq;
        } idseq;

        uint32_t sih_void;

        struct pmtu
        {
            uint16_t ipm_void;
            uint16_t nextmtu;
        } pmtu;

        struct rtradv
        {
            uint8_t num_addrs;
            uint8_t wpa;
            uint16_t lifetime;
        } rtradv;
    } icmp_hun;

#define s_icmp_pptr       icmp_hun.param.pptr
#define s_icmp_gwaddr     icmp_hun.gwaddr
#define s_icmp_id         icmp_hun.idseq.id
#define s_icmp_seq        icmp_hun.idseq.seq
#define s_icmp_void       icmp_hun.sih_void
#define s_icmp_pmvoid     icmp_hun.pmtu.ipm_void
#define s_icmp_nextmtu    icmp_hun.pmtu.nextmtu
#define s_icmp_num_addrs  icmp_hun.rtradv.num_addrs
#define s_icmp_wpa        icmp_hun.rtradv.wpa
#define s_icmp_lifetime   icmp_hun.rtradv.lifetime

    union
    {
        /* timestamp */
        struct ts
        {
            uint32_t otime;
            uint32_t rtime;
            uint32_t ttime;
        } ts;

        /* IP header for unreach */
        struct ih_ip
        {
            IPHdr *ip;
            /* options and then 64 bits of data */
        } ip;

        struct ra_addr
        {
            uint32_t addr;
            uint32_t preference;
        } radv;

        uint32_t mask;

        char    data[1];

    } icmp_dun;
#define s_icmp_otime      icmp_dun.ts.otime
#define s_icmp_rtime      icmp_dun.ts.rtime
#define s_icmp_ttime      icmp_dun.ts.ttime
#define s_icmp_ip         icmp_dun.ih_ip
#define s_icmp_radv       icmp_dun.radv
#define s_icmp_mask       icmp_dun.mask
#define s_icmp_data       icmp_dun.data

}ICMPHdr;

//此结构体用于发送信息。
typedef struct message
{
	uint32_t id;
	uint8_t alertmsg[256];
	uint32_t seconds;//秒
	uint32_t microseconds;//微秒
	uint32_t sig_generator;   //snort哪一部分生成了alert。
	uint32_t sig_id;  //规则的ID
	char type[256]; //攻击类型；
	uint32_t priority; //攻击优先级
	char src_ip[16];
	char dst_ip[16];
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t ether_dst[6];   //目的MAC
    uint8_t ether_src[6];   //源MAC
	
}message;

int sockfd;//套接字标识符，用于和snort通信。



/*
 * 捕捉到中断信号后执行。
 */
void sig_term (int sig)
{
  printf ("Exiting!\n");
  close (sockfd);
  unlink (UNSOCK_FILE);
  exit (1);
}


//自定义的协议数据类型变量；
const EtherHdr *eh;  //MAC
const IPHdr *iph;    // IP
const TCPHdr *tcph;  // TCP
const UDPHdr *udph;  //  UDP
const ICMPHdr *icmph;  // ICMP
const uint8_t *pkt;    //  包的有效载荷。
const uint8_t *data;   //包的有效载荷。

message msg;

int main (void)
{
	//先读取分类文件表：
	char classification_buff[128][256];
    char description_buff[128][256];
    char * file_classification = "classification.txt";
    char * file_describtion = "description.txt";

    FILE *fp_c ;
    FILE *fp_d ;
    int count=1;

    fp_c = fopen(file_classification,"r");
    fp_d = fopen(file_describtion,"r");

    if( fp_c == NULL || fp_d == NULL)
    {
        printf("can't open file!!!\n");
        return 1;
    }

    while (! feof(fp_c) )
    {
        fgets( classification_buff[count++], 256, fp_c );
    }
    count=1;
	
    while (! feof(fp_d) )
    {
        fgets( description_buff[count++], 256, fp_d );
    }

	//开始配置套接字通信。用于发送警报给控制器。
	int client_sockfd;  //网络套接字。
    int send_len; //发送出去的字节数。
    struct sockaddr_in remote_addr; //服务器端网络地址。
	//以下设置网络通信的服务器地址信息。
    memset(&remote_addr,0,sizeof(remote_addr)); //数据初始化--清零
    remote_addr.sin_family=AF_INET; //设置为IP通信  
    remote_addr.sin_addr.s_addr=inet_addr("127.0.0.1");//服务器IP地址  
    remote_addr.sin_port=htons(8000); //服务器端口号  
	
	//以下是网络通信，创建客户端套接字--IPv4协议，面向连接通信，TCP协议 
	if( ( client_sockfd = socket(PF_INET,SOCK_STREAM,0) ) <0 )  
	{  
		perror("socket error");  
		return 1;  
	}  
      
	//将套接字绑定到服务器的网络地址上。服务器端要监听8000端口号。
	if( connect(client_sockfd, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr) ) <0 )  
	{  
		perror("connect error");  
		return 1;  
	}  
	printf("......................\n");   
	printf("connected to server\n");   
	printf("sending alert message to controller......\n");
	printf("......................\n\n");  
	
//////////////////分割//////////////////////////////////

	//以下是本地套接字通信。用于接收snort发送的警报。
	//进程间通信的一种方式是使用UNIX套接字:sockaddr_un.
	struct sockaddr_un snortaddr;
	struct sockaddr_un bogus;
	
	Alertpkt alert;  //snort报警发出的数据包。
	int recv;//从本地套接字接收到的字节数。
	socklen_t len = sizeof (struct sockaddr_un);

	//生成和snort通信的套接字。
	if ((sockfd = socket (AF_UNIX, SOCK_DGRAM, 0)) < 0)
    {
		perror ("socket");
		exit (1);
    }

	//本地通信地址信息处理。
	bzero (&snortaddr, sizeof (snortaddr)); //置字节字符串前n个字节为零且包括‘\0’。
	snortaddr.sun_family = AF_UNIX; //协议类型。
	strcpy (snortaddr.sun_path, UNSOCK_FILE); //生成套接字地址。

	//将套接字和地址绑定，用于监听套接字的消息。
	if (bind (sockfd, (struct sockaddr *) &snortaddr, sizeof (snortaddr)) < 0)
    {
		perror ("bind");
		exit (1);
    }
	
	signal(SIGINT, sig_term);  //设置某一中断信号的对应动作。
	
	struct tm *local_time;//结构体，存储年月日等。
	char time_buffer[64],buf[64];
	struct timeval time64; //结构体，存储秒和微秒
	time_t nowtime; //64位整型
		
	//函数原型:int recvfrom(SOCKET s,  void *buf,  int len,  unsigned int flags,  struct sockaddr *from,  int *fromlen);
	//用于接收报警消息。
	while ((recv = recvfrom (sockfd, (void *) &alert, sizeof (alert), 0, (struct sockaddr *) &bogus, &len) ) > 0)
    {

		uint32_t microseconds = alert.event.ref_time.tv_usec;
		uint32_t microseconds_cap = alert.pkth.ts.tv_usec;
		
		msg.id = alert.event.event_id;
		strcpy(msg.alertmsg, alert.alertmsg);
		msg.seconds = alert.event.ref_time.tv_sec;
		msg.microseconds = alert.event.ref_time.tv_usec;
		msg.sig_generator = alert.event.sig_generator;
		msg.sig_id = alert.event.sig_id;
		strcpy(msg.type, classification_buff[alert.event.classification]);
		msg.priority = alert.event.priority;

		//时间格式转换。
		gettimeofday((struct timeval*)&alert.event.ref_time,NULL);
		nowtime = alert.event.ref_time.tv_sec + 8*3600; //格林威治时间加8个小时得到北京时间。
		local_time = localtime(&nowtime);
		strftime(time_buffer, sizeof time_buffer, "%Y年-%m月-%d日  %H:%M:%S", local_time);
		
		printf ("第【%d】个警报：\n", alert.event.event_id);
		printf ("警报消息: %s\n", alert.alertmsg);	
		printf ("警报时间: %s.%06u\n", time_buffer, microseconds );
		printf ("发出警报的部件ID: %lu\n", (unsigned long) alert.event.sig_generator );
		printf ("触发警报的规则ID: %lu\n", (unsigned long) alert.event.sig_id );
		printf ("检测到的攻击类型: 编号[%d] %s", alert.event.classification,classification_buff[alert.event.classification] );
		printf ("攻击描述: %s", description_buff[alert.event.classification] );
		printf ("攻击的优先级: %d\n", alert.event.priority );
		
 
		gettimeofday((struct timeval*)&alert.pkth.ts,NULL);
		nowtime = alert.pkth.ts.tv_sec + 8*3600;//格林威治时间加8个小时得到北京时间。
		local_time = localtime(&nowtime);
		strftime(time_buffer, sizeof time_buffer, "%Y年-%m月-%d日  %H:%M:%S", local_time);
		
		printf("捕捉到数据包时间: %s\n", time_buffer);//没有精确到微秒。因为不知为何，这里的微秒时间是0.
		printf ("捕捉到数据包的大小 captured_length: %u\n", alert.pkth.caplen);
		//printf ("捕捉到数据包的净载荷 real_length:%u\n", alert.pkth.len);//这里的值是0，原因未知。	 
		
		pkt = alert.pkt;  // uint8_t pkt[65535]; raw packet data
		eh = (EtherHdr *) (alert.pkt + alert.dlthdr);
		
		//打印MAC地址。
		printf("源MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->ether_src[0],eh->ether_src[1],eh->ether_src[2],eh->ether_src[3],eh->ether_src[4],eh->ether_src[5]);
		printf("目的MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->ether_dst[0],eh->ether_dst[1],eh->ether_dst[2],eh->ether_dst[3],eh->ether_dst[4],eh->ether_dst[5]);
		
		memcpy((void *)msg.ether_dst, (void *)eh->ether_dst, 6);
		memcpy((void *)msg.ether_src, (void *)eh->ether_src, 6);
		
		if (alert.nethdr) //如果有IP信息。
            {
				iph = (IPHdr *) (alert.pkt + alert.nethdr);
			
				//if (alert.transhdr)//如果有传输层协议信息。
                //{
					
					switch (iph->ip_proto) 
                    {
                    case IPPROTO_TCP:
						tcph = (TCPHdr *) (alert.pkt + alert.transhdr);
						printf("TCP source IP and PORT: %s:%u\n",inet_ntoa (iph->ip_src),ntohs ( tcph->th_sport));
						printf("TCP destination IP and PORT: %s:%u\n",inet_ntoa (iph->ip_dst),ntohs ( tcph->th_dport));
						msg.src_port = ntohs (tcph->th_sport);
						msg.dst_port = ntohs (tcph->th_dport);
						break;
						
                    case IPPROTO_UDP:
						udph = (UDPHdr *) (alert.pkt + alert.transhdr);
						printf("UDP source IP and PORT: %s:%u\n",inet_ntoa (iph->ip_src),ntohs ( udph->uh_sport));
						printf("UDP destination IP and PORT: %s:%u\n",inet_ntoa (iph->ip_dst),ntohs ( udph->uh_dport));
						msg.src_port = udph->uh_sport;
						msg.dst_port = udph->uh_dport;
						break;
						
                    case IPPROTO_ICMP:
						icmph = (ICMPHdr *) (alert.pkt + alert.transhdr);
						printf ("ICMP type: %d \n",icmph->type);
						printf ("ICMP code: %d  \n",icmph->code);
						printf("ICMP source IP: %s\n",inet_ntoa (iph->ip_src));
						printf("ICMP destination IP: %s\n",inet_ntoa (iph->ip_dst));
						break;
						
                    default:
						printf ("My, that's interesting.\n");
                    } 

					//复制IP地址信息。
					int len_src, len_dst;
					len_src = strlen(inet_ntoa (iph->ip_src));
					len_dst = strlen(inet_ntoa (iph->ip_dst));
					
					if( len_src <=15 && len_dst <=15)
					{
						memcpy(msg.src_ip, inet_ntoa (iph->ip_src), len_src );
						memcpy(msg.dst_ip, inet_ntoa (iph->ip_dst), len_dst );
						msg.src_ip[len_src] = '\0';
						msg.dst_ip[len_dst]  = '\0';
					}
					else
					{
						printf("复制error");
						exit(1);
					}					
               // }  //thanshdr 
            } /// nethdr 
		
			
		/*测试用的代码。
			printf("alert.nethdr:%d\n",alert.nethdr);
			printf("alert.transhdr:%d\n",alert.transhdr);
			printf("iph->ip_proto:%d\n",iph->ip_proto);
			printf("IPPROTO_TCP:%d\n",IPPROTO_TCP);
			printf("IPPROTO_UDP:%d\n",IPPROTO_UDP);
			printf("IPPROTO_ICMP:%d\n",IPPROTO_ICMP);
	     */
  
		/*测试用的代码。
			printf("msg.id: %d\n",msg.id);
			printf("msg.alertmsg: %s\n",msg.alertmsg);
			printf("msg.seconds: %d\n",msg.seconds);
			printf("msg.microseconds: %d\n",msg.microseconds);
			printf("msg.sig_generator: %d\n",msg.sig_generator);
			printf("msg.sig_id: %d\n",msg.sig_id);
			printf("msg.type: %s",msg.type);
			printf("msg.priority: %d\n",msg.priority);
			printf("msg.src_ip: %s\n",msg.src_ip);
			printf("msg.dst_ip: %s\n",msg.dst_ip);
			printf("msg.src_port: %u\n",msg.src_port);
			printf("msg.dst_port: %u\n",msg.dst_port);
			printf("msg.ether_dst %02X:%02X:%02X:%02X:%02X:%02X\n",msg.ether_dst[0],msg.ether_dst[1],msg.ether_dst[2],msg.ether_dst[3],msg.ether_dst[4],msg.ether_dst[5]);
			printf("msg.ether_src %02X:%02X:%02X:%02X:%02X:%02X\n",msg.ether_src[0],msg.ether_src[1],msg.ether_src[2],msg.ether_src[3],msg.ether_src[4],msg.ether_src[5]);
		*/
		
		send_len=send(client_sockfd,(void *)&msg, sizeof(msg),0);
		printf ("\n");

    }
	
	perror ("recvfrom");
	close (sockfd);
	close(client_sockfd);
	fclose(fp_c);
    fclose(fp_d);
	unlink (UNSOCK_FILE);

	return 0;
}
