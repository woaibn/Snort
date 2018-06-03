/*
这段程序用于接收客户端的报警消息。
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
////////////////////////////
#define UNSOCK_FILE "snort_alert" //套接字文件名称。



//自定义。
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
 * 捕捉到信号后执行。
 */
void sig_term (int sig)
{
  printf ("Exiting!\n");
  close (sockfd);
  unlink (UNSOCK_FILE);
  exit (1);
}

int main(int argc, char *argv[])  
{  
    int server_sockfd;//服务器端套接字 
    int client_sockfd;//客户端套接字  
	
    int len;  
    struct sockaddr_in my_addr;   //服务器网络地址结构体  
    struct sockaddr_in remote_addr; //客户端网络地址结构体  
	
    int sin_size;  
    memset(&my_addr,0,sizeof(my_addr)); //数据初始化--清零  
    my_addr.sin_family=AF_INET; //设置为IP通信  
    my_addr.sin_addr.s_addr=INADDR_ANY;//服务器IP地址--允许连接到所有本地地址上  
    my_addr.sin_port=htons(8000); //服务器端口号  
      
    /*创建服务器端套接字--IPv4协议，面向连接通信，TCP协议*/  
    if((server_sockfd = socket(PF_INET,SOCK_STREAM,0))<0)  
    {    
        perror("socket error");  
        return 1;  
    }  
  
  
    /*将套接字绑定到服务器的网络地址上*/  
    if(bind(server_sockfd,(struct sockaddr *)&my_addr,sizeof(struct sockaddr))<0)  
    {  
        perror("bind error");  
        return 1;  
    }  
      
    /*监听连接请求--监听队列长度为5*/  
    if(listen(server_sockfd,5)<0)  
    {  
        perror("listen error");  
        return 1;  
    };  
      
    sin_size=sizeof(struct sockaddr_in);  
      
    /*等待客户端连接请求到达*/  
    if( (client_sockfd = accept(server_sockfd,(struct sockaddr *)&remote_addr,&sin_size))<0)  
    {  
        perror("accept error");  
        return 1;  
    }  
	   
	message msg;  //用于接收snort报警。
    while( ( len = recv(client_sockfd,(void *) &msg, sizeof (msg),0) ) > 0 )  
    { 
		printf("accept client IP %s\n",inet_ntoa(remote_addr.sin_addr));  
		
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

		printf ("\n");
	  
    }  
  
  
    /*关闭套接字*/  
    close(client_sockfd);  
    close(server_sockfd);  
      
    return 0;  
} 
