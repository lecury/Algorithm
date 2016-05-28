#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <getopt.h>
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h> 
#include <netinet/udp.h> 
#include <netinet/ip_icmp.h> 
#include <net/if.h> 
#include <sys/ioctl.h> 
#include <fcntl.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h> 

#define INTERFACE "eth0"                      /* 网卡 */ 
#define BUF_SIZE 8192
#define MAX_PROTO 3

const int protocol_array[] = {
	IPPROTO_TCP,
	IPPROTO_UDP,
	IPPROTO_ICMP
};
const char * protocol_str[] = {
	"TCP",
	"UDP",
	"ICMP"
};
const char * icmp_type[] = {
	"ECHOREPLY",
	"",
	"",
	"DEST_UNREACH",
	"SOURCE_QUENCH",
	"REDIRECT",
	"",
	"",
	"ECHO",
	"",
	"",
	"TIME_EXCEEDED",
	"PARAMETERPROB",
	"TIMESTAMP",
	"TIMESTAMPREPLY",
	"INFO_REQUEST",
	"INFO_REPLY",
	"ADDRESS",
	"ADDRESSREPLY"
};
const char * icmp_code[] = {
	"ICMP_NET_UNREACH",
	"ICMP_HOST_UNREACH",
	"ICMP_PROT_UNREACH",
	"ICMP_PORT_UNREACH",
	"ICMP_FRAG_NEEDED",
	"ICMP_SR_FAILED",
	"ICMP_NET_UNKNOWN",
	"ICMP_HOST_UNKNOWN",
	"ICMP_HOST_ISOLATED",
	"ICMP_NET_ANO",
	"ICMP_HOST_ANO",
	"ICMP_NET_UNR_TOS",
	"ICMP_HOST_UNR_TOS",
	"ICMP_PKT_FILTERED",
	"ICMP_PREC_VIOLATION",
	"ICMP_PREC_CUTOFF"
};

void help()
{
	printf("\n\t\t\tPacket Sniffer\t\t\t\n\n");
	printf("\t--protocol | -p \ttcp:0 | udp:1 | icmp:2\n");
	printf("\t--port | -d \tset port number\n");
	printf("\t--help | -h \tprint help info\n\n");
	printf("\tEXAMPLE : ./snf --protocol = tcp -port = 80 \n");
	printf("\tEXAMPLE : ./snf --p 0 -d 80 \n\n");
	printf("\t\t\t\t\tAuthor : Liu Chang\n");
	printf("\t\t\t\t\tDate : 2016.5.28\n\n");
}

void report_error()
{
	printf("Input Error! Try ./snf --help\n");
}

void print_ip_header( struct iphdr * ip, unsigned short protocol )
{
	struct in_addr src_addr, dst_addr;

	src_addr.s_addr = ip->saddr;
	dst_addr.s_addr = ip->daddr;
	printf("\n\t\t\t\t\t IP Packet Header \t\t\t\t\t\n");
	printf("|\tHeader_length : %d\t", ip->ihl * 4 );
	printf("|\tProtocol : %s\t", protocol_str[protocol] );
	printf("|\t%s => %s \n", inet_ntoa(src_addr), inet_ntoa(dst_addr) );
	printf("|\tTotal_length : %d\t", ip->tot_len );
	printf("|\tID : %d\t", ip->id );
	printf("|\tTTL : %d\n", ip->ttl );
}

void print_tcp_header( struct tcphdr * tcp )
{
	printf("\t\t\t\t\t TCP Packet Header \t\t\t\t\t\n");
	printf("|\tHeader_length : %d\t", tcp->doff * 4 );
	printf("|\tSrc_port : %d\t", tcp->source );
	printf("|\tDst_port : %d\n", tcp->dest );
	printf("|\tSeq_num : %u\t", tcp->seq );
	printf("|\tAck_num : %u\t", tcp->ack_seq );
	printf("|\tWindow_size : %u\n\n", tcp->window );
}

void print_udp_header( struct udphdr * udp )
{
	printf("\t\t\t\t\t UDP Packet Header \t\t\t\t\t\n");
	printf("|\tHeader_length : %u\t", udp->len );
	printf("|\tCheck_sum : %u\n", udp->check );
	printf("|\tSrc_port : %d\t", udp->source );
	printf("|\tDst_port : %d\n", udp->dest );
}

void print_icmp_header( struct icmphdr * icmp )
{
	printf("\t\t\t\t\t ICMP Packet Header \t\t\t\t\t\n");
	printf("|\tType : %s\t", icmp_type[icmp->type] );
	printf("|\tCode : %s\t", icmp_code[icmp->code] );
	printf("|\tCheck_sum : %u\n", icmp->checksum );
}
/* 设置混杂模式 */
int set_promisc(char *interface,int sock)
{ 
	struct ifreq ifr; 

	strncpy(ifr.ifr_name, interface,strlen(interface)+1); 

	if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)) { 

		printf("Could not retrive flags for the interface/n"); 
		return -1; 
	} 

	ifr.ifr_flags |= IFF_PROMISC; 

	if(ioctl(sock, SIOCSIFFLAGS, &ifr) == -1 ) { 
		printf("Could not set the PROMISC flag./n"); 
		return -1; 
	} 

	printf("Setting interface %s to promisc/n", interface); 
	return -1;
} 

int main( int argc, char ** argv ) 
{ 
	unsigned short protocol = IPPROTO_TCP;
	unsigned short port = 80;
	char choice;
	
	static const char * short_option = "p:d:h";
	static struct option long_option[] = {
		{ "protocol", required_argument, NULL, 'p' },
		{ "port", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};

	while( (choice = getopt_long(argc, argv, short_option, long_option, NULL) ) != -1 ) {
		switch( choice ) {
			case 'p':
				if( *optarg >= '0' && *optarg <= '9' ) {
					protocol = atoi(optarg);
					if( protocol >= MAX_PROTO ) {
						printf("Only support %d protocol..\n", MAX_PROTO );
						return 0;
					}
				}
				else {
					if( strcmp( optarg, "TCP" ) == 0 
					 || strcmp( optarg, "tcp" ) == 0 ) {
						protocol = 0;
					}
					else if( strcmp( optarg, "UDP" ) == 0 
						|| strcmp( optarg, "udp" ) == 0 ) {
						protocol = 1;
					}
					else if( strcmp( optarg, "ICMP" ) == 0 
						|| strcmp( optarg, "icmp" ) == 0 ) {
						protocol = 2;
					}
					else {
						report_error();
						return 0;
					}
				}
				break;
			case 'd':
				port = atoi(optarg);
				break;
			case 'h':
				help();
				return 0;
			default:
				report_error();
				return 0;
		}
	}

	printf("Your's action is to sniffer : %s : %d\n\n", protocol_str[protocol], port );

	struct sockaddr_in addr; 
	struct iphdr *ip; 
	struct tcphdr * tcp;
	struct udphdr * udp;
	struct icmphdr * icmp;

	char buffer[BUF_SIZE]; 
	int sockfd,byte_size,addrlen; 

	addrlen = sizeof(addr); 

	if(( sockfd = socket( AF_INET, SOCK_RAW, protocol_array[protocol] ) ) == -1) {   /* 使用SOCK_RAW */ 
		printf("socket failt /n"); 
		exit(0); 
	} 
	else {
		printf("RAW SOCKET create OK\n");
	}

	if( set_promisc(INTERFACE,sockfd) ) printf("set_promisc OK\n");

	while(1) 
	{ 
		byte_size = recvfrom(sockfd,(char *)&buffer,sizeof(buffer),
				0,(struct sockaddr *)&addr,&addrlen); 
		/* 格式化为IP数据包的头部 */
		ip = (struct iphdr *)buffer;                   
		print_ip_header( ip, protocol );

		switch( protocol ) {
			case 0 :
				tcp = (struct tcphdr *)(buffer + (ip->ihl >> 2));
			//	if( tcp->source != port || tcp->dest != port ) break;
				print_tcp_header( tcp );
				break;
			case 1 :
				udp = (struct udphdr *)(buffer + (ip->ihl >> 2));
			//	if( udp->source != port || udp->dest != port ) break;
				print_udp_header( udp );
				break;
			case 2 :
				icmp = (struct icmphdr *)(buffer + (ip->ihl >> 2));
				print_icmp_header( icmp );
				break;
			default :
				printf("Unexcepted error happended\n");
				exit(0);
		}
	} 

	return 0;
} 
