/* resolv.c: DNS Resolver
 *
 * Copyright (C) 1998	Kenneth Albanowski <kjahds@kjahds.com>,
 *										 The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
*/

/* Simplied with dnsmasq for embedded system.	--- 2008-03-20 */
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>
#include <ctype.h>
#include <arpa/nameser.h>
#include <sys/utsname.h>
#include <sys/un.h>
#include <nvram.h>

//#define nvram_safe_get(name) (nvram_get(name) ? : "")

#define PKTSIZE		512
#define MAXRETRIES 	3
#define DNS_HFIXEDSZ		12	/* bytes of fixed data in header */
#define DNS_RRFIXEDSZ	10	/* bytes of fixed data in r record */
#define DNS_PORT	53
#define DNS_IPADDR	0xc0254901	/* local nameserver: 127.0.0.1 */
#define DNS_TIMEOUT	3

#define NS_T_A	1	/* Host address. */
#define NS_C_IN	1	/* Internet. */
#define IP_QUAD(ip)  (ip)>>24,((ip)&0x00ff0000)>>16,((ip)&0x0000ff00)>>8,((ip)&0x000000ff)
#define IP_HEX(ipstr) (((ipstr[0])<< 24) | ((ipstr[1]) << 16) | ((ipstr[2]) << 8) | ((ipstr[3])))

int step;/* for dns lookup */

#if __linux__ || defined(__CYGWIN__)
extern int igd_check;
extern char grequested_ip[32];
#endif

static char *argv0;

/* Structs */
struct resolv_header 
{
	int id;
	int qr,opcode,aa,tc,rd,ra,rcode;
	int qdcount;
	int ancount;
	int nscount;
	int arcount;
};

struct resolv_question 
{
	char *dotted;
	int qtype;
	int qclass;
};

struct resolv_answer 
{
	int atype;
	int aclass;
	int rdlength;
	unsigned char *rdata;
};

#if defined(darwin) || defined(__APPLE__) || defined(MACOSX)
//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;
static char *argv0;
//Types of DNS resource records :)

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#ifdef DEBUG
#define LOG		printf
#else
#define LOG
#endif

//Function Prototypes
char *ngethostbyname (unsigned char* , int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();

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
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;

unsigned int ip_addr;
/*
 * Perform a DNS query by sending a packet
 * */
char *ngethostbyname(unsigned char *host , int query_type)
{
	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , s;

	struct sockaddr_in a;

	struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	LOG("Resolving %s" , host);

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
#ifndef _nvram_h_
	dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns servers
#else
	dest.sin_addr.s_addr = inet_addr(nvram_safe_get("wan0_dns")); //dns servers
#endif

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	ChangetoDnsNameFormat(qname , host);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = htons(1); //its internet (lol)

	LOG("\nSending Packet...");
	if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		perror("sendto failed");
	}
	LOG("Done");
	
	//Receive the answer
	i = sizeof dest;
	LOG("\nReceiving answer...");
	if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("recvfrom failed");
	}
	LOG("Done");

	dns = (struct DNS_HEADER*) buf;

	//move ahead of the dns header and the query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	LOG("\nThe response contains : ");
	LOG("\n %d Questions.",ntohs(dns->q_count));
	LOG("\n %d Answers.",ntohs(dns->ans_count));
	LOG("\n %d Authoritative Servers.",ntohs(dns->auth_count));
	LOG("\n %d Additional records.\n\n",ntohs(dns->add_count));

	//Start reading answers
	stop=0;

	for(i=0;i<ntohs(dns->ans_count);i++)
	{
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
		{
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(answers[i].resource->data_len);
		}
		else
		{
			answers[i].rdata = ReadName(reader,buf,&stop);
			reader = reader + stop;
		}
	}

	//read authorities
	for(i=0;i<ntohs(dns->auth_count);i++)
	{
		auth[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		auth[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		auth[i].rdata=ReadName(reader,buf,&stop);
		reader+=stop;
	}

	//read additional
	for(i=0;i<ntohs(dns->add_count);i++)
	{
		addit[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		if(ntohs(addit[i].resource->type)==1)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(j=0;j<ntohs(addit[i].resource->data_len);j++)
			addit[i].rdata[j]=reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		}
		else
		{
			addit[i].rdata=ReadName(reader,buf,&stop);
			reader+=stop;
		}
	}

	//print answers
	LOG("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
	for(i=0 ; i < ntohs(dns->ans_count) ; i++)
	{
		LOG("Name : %s ",answers[i].name);

		if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
		{
			long *p;
			p=(long*)answers[i].rdata;
			a.sin_addr.s_addr=(*p); //working without ntohl
			LOG("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		
		if(ntohs(answers[i].resource->type)==5) 
		{
			//Canonical name for an alias
			LOG("has alias name : %s",answers[i].rdata);
		}

		LOG("\n");
	}

	//print authorities
	LOG("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
	for( i=0 ; i < ntohs(dns->auth_count) ; i++)
	{
		
		LOG("Name : %s ",auth[i].name);
		if(ntohs(auth[i].resource->type)==2)
		{
			LOG("has nameserver : %s",auth[i].rdata);
		}
		LOG("\n");
	}

	//print additional resource records
	LOG("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
	for(i=0; i < ntohs(dns->add_count) ; i++)
	{
		LOG("Name : %s ",addit[i].name);
		if(ntohs(addit[i].resource->type)==1)
		{
			long *p;
			p=(long*)addit[i].rdata;
			a.sin_addr.s_addr=(*p);
			LOG("has IPv4 address : %s",inet_ntoa(a.sin_addr));
		}
		LOG("\n");
	}

	unsigned char *ip = answers[0].rdata;
	ip_addr = IP_HEX(ip);
	return inet_ntoa(a.sin_addr);
}

/*
 * 
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
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

/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
void get_dns_servers()
{
	FILE *fp;
	char line[200] , *p;
	if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
	{
		LOG("Failed opening /etc/resolv.conf file \n");
	}
	
	while(fgets(line , 200 , fp))
	{
		if(line[0] == '#')
		{
			continue;
		}
		if(strncmp(line , "nameserver" , 10) == 0)
		{
			p = strtok(line , " ");
			p = strtok(NULL , " ");
			
			//p now is the dns ip :)
			//????
		}
	}
	
	strcpy(dns_servers[0] , "208.67.222.222");
	strcpy(dns_servers[1] , "208.67.220.220");
}

/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
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
#endif

int cmp_dns_ip(char * dns, char *ip)
{
	char buf[64]={'\0'};
	char *delim=" ";
	char *pdns=NULL;
	
	//printf("%s: %s\n", __func__, dns);
	if(dns){
		strcpy(buf,dns);
		pdns=strtok(buf,delim);
		do{
			if(!strcmp(pdns, ip)){
				printf("%s: ** Same IP %s **\n", __func__, ip);
				return 1;
			}
			pdns=strtok(NULL,delim);
		}while(pdns);
	}
	return 0;
}

/* 
	* Encode a dotted string into nameserver transport-level encoding.
	* and the dest is BIG enough. 
	* g e m i n i . t u c . n o a o . e d u
	* [6] g e m i n i [3] t u c [4] n o a o [3] e d u[0]
	*/
static int __encode_dotted(const char *dotted, unsigned char *dest)
{
	char c;
	int used, len;
	unsigned char *plen;

	len = 0, used = 1;
	plen = &dest[0];
	
	while ((c = *dotted++) != '\0') {
		if (c == '.') {
			*plen = (unsigned char)len;
			len = 0, plen = &dest[used++];
			continue;
		}

		dest[used++] = (unsigned char)c;
		len++;
	}

	*plen = (unsigned char)len;
	dest[used++] = 0;

	return used;
}

static int __length_dotted(unsigned char *data, int offset)
{
	int len, orig = offset;
	
	while ((len = data[offset++])) {
		if ((len & 0xC0) == 0xC0) { /* compress */
			offset++;
			break;
		}

		offset += len;
	}

	return offset - orig;
}

/* The dest is BIG enough */
static int __encode_question(struct resolv_question *q, unsigned char *dest)
{
	int i;

	i = __encode_dotted(q->dotted, dest);
	
	dest += i;

	dest[0] = (q->qtype & 0xFF00) >> 8;
	dest[1] = (q->qtype & 0x00FF) >> 0;
	dest[2] = (q->qclass & 0xFF00) >> 8;
	dest[3] = (q->qclass & 0x00FF) >> 0;

	return i + 4;
}

static int __decode_answer(unsigned char *message, int offset,
			struct resolv_answer *a)
{
	int i;

	i = __length_dotted(message, offset);
	
	message += offset + i;

	a->atype = (message[0] << 8) |message[1]; 
	message += 2;
	a->aclass = (message[0] << 8) |message[1]; 
	message += 6; /* skip ttl */
	a->rdlength = (message[0] << 8) |message[1];
	message += 2;
	a->rdata = message;

	return i + DNS_RRFIXEDSZ + a->rdlength;
}

static int __length_question(unsigned char *message, int offset)
{
	int i;

	i = __length_dotted(message, offset);

	return i + 4;
}

static int __encode_header(struct resolv_header *h, unsigned char *dest)
{
	dest[0] = (h->id & 0xFF00) >> 8;
	dest[1] = (h->id & 0x00FF) >> 0;
	dest[2] = (h->qr ? 0x80 : 0) |
			((h->opcode & 0x0F) << 3) |
			(h->aa ? 0x04 : 0) |
			(h->tc ? 0x02 : 0) |
			(h->rd ? 0x01 : 0);
	dest[3] = (h->ra ? 0x80 : 0) | (h->rcode & 0x0F);
	dest[4] = (h->qdcount & 0xFF00) >> 8;
	dest[5] = (h->qdcount & 0x00FF) >> 0;
	dest[6] = (h->ancount & 0xFF00) >> 8;
	dest[7] = (h->ancount & 0x00FF) >> 0;
	dest[8] = (h->nscount & 0xFF00) >> 8;
	dest[9] = (h->nscount & 0x00FF) >> 0;
	dest[10] = (h->arcount & 0xFF00) >> 8;
	dest[11] = (h->arcount & 0x00FF) >> 0;

	return DNS_HFIXEDSZ;
}

static void __decode_header(struct resolv_header *h, unsigned char *data)
{
	h->id = (data[0] << 8) | data[1];
	h->qr = (data[2] & 0x80) ? 1 : 0;
	h->opcode = (data[2] >> 3) & 0x0F;
	h->aa = (data[2] & 0x04) ? 1 : 0;
	h->tc = (data[2] & 0x02) ? 1 : 0;
	h->rd = (data[2] & 0x01) ? 1 : 0;
	h->ra = (data[3] & 0x80) ? 1 : 0;
	h->rcode = data[3] & 0x0F;
	h->qdcount = (data[4] << 8) | data[5];
	h->ancount = (data[6] << 8) | data[7];
	h->nscount = (data[8] << 8) | data[9];
	h->arcount = (data[10] << 8) | data[11];
}

#define OPEN_UDP(fd) (fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))
#define SOCKTYPE(dest) ((struct sockaddr const *)(dest))

static gsameip=0;

#if __linux__ || defined(__CYGWIN__)
void lanip_would_off()
{
	char cmd[64]={'\0'};
	/* check DHCP only */
	if((igd_check==1) && (step==0)){
		if(cmp_dns_ip(nvram_safe_get("wan0_dns"), nvram_safe_get("lan_ipaddr")?:"...") ||
		 (!strcmp(grequested_ip,nvram_safe_get("lan_ipaddr")?:"..."))){
			/* if WAN ip is the same as lan_ip or dns ip */
			sprintf(cmd, "ifconfig br0 0.0.0.0");
			system(cmd);
			gsameip=1;
		}
	}
}

void lanip_would_up()
{
	char cmd[64]={'\0'};
	/* check same IP between LAN ip and DNS in DHCP detection only */
	if((igd_check==1) && (step==0) && (gsameip == 1)){
		sprintf(cmd, "ifconfig br0 %s up", nvram_safe_get("lan_ipaddr"));
		system(cmd);
		gsameip=0;
	}
}
#endif

/* modified from uclib function '__dns_lookup', just inet type */
static unsigned int dns_lookup(char *name, int hijack)
{
	int sock_raw;
	int retries = -1;
	int local_id = 1313;
	unsigned int ipaddr = 0;
	int i, j, len, fd, pos,ind=0;
	fd_set readable;
	struct timeval timeo;
	struct sockaddr_in dest;
	struct resolv_header h;
	struct resolv_question q;
	struct resolv_answer ma;
	unsigned char packet[PKTSIZE];

	struct hostent *hp;
	struct in_addr in;
	struct sockaddr_in local_addr;
#if __linux__ || defined(__CYGWIN__)
	 struct ifreq interface;
#elif defined(__FreeBSD__) || defined(__APPLE__) || defined(MACOSX) || defined(darwin)
 	char *ethInterface = nvram_safe_get("wan_ifname");
#endif
	char *wan_dns = NULL, *tmp_dns, *default_ind,*wan_proto,*easy_wan_mode;
	char str[16];


	wan_proto=nvram_safe_get("wan_proto");
	easy_wan_mode=nvram_safe_get("easy_wan_mode");
	if( (!strcmp(wan_proto,"pppoe")) || (!strcmp(wan_proto,"unnumber")) || (!strcmp(wan_proto,"easy") && !strcmp(easy_wan_mode,"pppoe"))){
		default_ind=nvram_safe_get("pppoe_default");
		if(*default_ind != '\0')
			ind=atoi(default_ind)-1;
	}else{
		ind=0;
	}
	sprintf(str,"wan%d_dns",ind);

		tmp_dns = nvram_safe_get(str);
		if (strlen(tmp_dns) > 1) {		
				wan_dns = strtok(tmp_dns, " ");				
		}
	printf("======dns_lookup %s=%s\n",str,tmp_dns);
		if (wan_dns == NULL) 
				return 0;

	if(hijack == 1){
		if((hp=gethostbyname(name))){
			memcpy(&local_addr.sin_addr.s_addr, hp->h_addr, 4);
			in.s_addr = local_addr.sin_addr.s_addr;
			printf("### ( %s ) IP address: %s\n",name, inet_ntoa(in));
			if(in.s_addr){
				ipaddr = inet_ntoa(in);
			}
		}
		goto ret;
	}else{
		fd = -1;
		memset(&dest, 0, sizeof(dest));
		dest.sin_family = AF_INET;
		dest.sin_port = htons(DNS_PORT);			
				dest.sin_addr.s_addr = inet_network(wan_dns); /* little-endian: use '127.0.0.1' as nameserver, it's dnsmasq */

#if __linux__ || defined(__CYGWIN__)
		lanip_would_off();
#endif
		while (++retries < MAXRETRIES) {
			if (fd < 0 && OPEN_UDP(fd) < 0)
				continue;

#if __linux__ || defined(__CYGWIN__)
		if (step == 0){
			strncpy(interface.ifr_ifrn.ifrn_name, "eth1", IFNAMSIZ);	// changed. before: eth0	after:eth1		//kcliang 20140929 
		}
		else
					{
						if(nvram_match("router_disable","0"))
							strncpy(interface.ifr_ifrn.ifrn_name, WAN_IFNAME, IFNAMSIZ); //router mode
			else{
				strncpy(interface.ifr_ifrn.ifrn_name, "br0", IFNAMSIZ); //bridge mode
			}
		}
#endif
		
#if __linux__ || defined(__CYGWIN__)
			sock_raw = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,(char *)&interface, sizeof(interface));
			//if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,(char *)&interface, sizeof(interface)) < 0) {
#elif defined(__FreeBSD__) || defined(__APPLE__) || defined(MACOSX) || defined(darwin)
			sock_raw = socket(AF_INET, SOCK_DGRAM, 0);
			//sock_raw = socket( PF_INET, SOCK_DGRAM, IPPROTO_IP );
			//sock_raw = setsockopt(fd, SOL_SOCKET, IP_RECVIF, &ethInterface, strlen(ethInterface));
			//if (setsockopt(fd, SOL_SOCKET, IP_RECVIF, &ethInterface, strlen(ethInterface)) < 0) {
#endif
			if(sock_raw < 0){
				close(fd);
#if __linux__ || defined(__CYGWIN__)
				lanip_would_up();
#endif
				return 0;
			}

			memset(packet, 0, PKTSIZE);

			memset(&h, 0, sizeof(h));
			h.id = ++local_id;
			h.qdcount = 1;
			h.rd = 1;
			i = __encode_header(&h, packet);

			q.dotted = name;
			q.qtype = NS_T_A;
			q.qclass = NS_C_IN;
			j = __encode_question(&q, packet + i);

			len = i + j;
			if (sendto(fd, packet, len, 0, SOCKTYPE(&dest), sizeof(dest)) < 1)
				continue;
	
			FD_ZERO(&readable);
			FD_SET(fd, &readable);
			timeo.tv_sec = DNS_TIMEOUT;
			timeo.tv_usec = 0;
			if (select(fd + 1, &readable, NULL, NULL, &timeo) < 1)
				continue;			

			len = recvfrom(fd, packet, sizeof(packet), 0, NULL, 0);
			if (len < DNS_HFIXEDSZ)
				continue;

			__decode_header(&h, packet);
			if (h.id != local_id ||!h.qr ||h.rcode ||h.ancount < 1)
				continue;

			pos = DNS_HFIXEDSZ;
			for (j = 0; j < h.qdcount; j++)
				pos += __length_question(packet, pos);

			for (j = 0; j < h.ancount; j++, pos += i) {
				i = __decode_answer(packet, pos, &ma);
				if (ma.atype != NS_T_A ||ma.aclass != NS_C_IN)
					continue;

				unsigned char *p = ma.rdata;
				ipaddr = (p[0] << 24) |(p[1] << 16) |(p[2] << 8) |(p[3]);
printf("\n------------------------------------------------------------------------\n");
				goto ret;
			}
		}
#if __linux__ || defined(__CYGWIN__)
				lanip_would_up();
#endif
	}

ret:
#if __linux__ || defined(__CYGWIN__)
		lanip_would_up();
#endif
	if (fd >= 0)
		close(fd);

	return ipaddr;
}

unsigned int resolve_dns(char *host, int blank_flag)
{
	unsigned int ipaddr;

	ipaddr = inet_addr(host);
	if (ipaddr == INADDR_NONE)
		ipaddr = dns_lookup(host,blank_flag);

	printf("ipaddr = %d.%d.%d.%d\n", ipaddr>>24, (ipaddr>>16)&0xff, (ipaddr>>8)&0xff, ipaddr&0xff);
	return ipaddr;
}

static char *base64enc(const char *p, char *buf, int len)
{
	char al[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		"0123456789+/";
	char *s = buf;

	while(*p) {
		if (s >= buf+len-4)
			break;
		*(s++) = al[(*p >> 2) & 0x3F];
		*(s++) = al[((*p << 4) & 0x30) | ((*(p+1) >> 4) & 0x0F)];
		*s = *(s+1) = '=';
		*(s+2) = 0;
		if (! *(++p)) break;
		*(s++) = al[((*p << 2) & 0x3C) | ((*(p+1) >> 6) & 0x03)];
		if (! *(++p)) break;
		*(s++) = al[*(p++) & 0x3F];
	}

	return buf;
}

#if 1

void usage()
{
	fprintf(stderr, "useage: %s url\n", argv0);
	exit(1);
}

int main(int argc, char **argv)
{
	char url[256] = { 0 }, *s, *server;
	char *host = url, *path = "", auth[128] = { 0 }, line[512];
	unsigned int ipaddr;
	unsigned short port = 80;
	struct sockaddr_in sin;

	nvram_set("wan0_dns", "192.37.73.1");
	argv0 = argv[0];
	if (argc != 2) {
		usage();
	}

	server = argv[1];
	LOG( "%s:: enters, server [%s]\n", __FUNCTION__, server ? server : "NULL" );
	if (server == NULL || !strcmp(server, "")) {
		printf("wget: null server input\n");
		return (0);
	}

	strncpy(url, server, sizeof(url));

	/* Parse URL */
	if (!strncmp(url, "http://", 7)) {
		port = 80;
		host = url + 7;
	}
	if ((s = strchr(host, '/'))) {
		*s++ = '\0';
		path = s;
	}
	if ((s = strchr(host, '@'))) {
		*s++ = '\0';
		base64enc(host, auth, sizeof(auth));
		host = s;
	}
	if ((s = strchr(host, ':'))) {
		*s++ = '\0';
		port = atoi(s);
	}


	/* Open socket */
	LOG("%s:: Translate host [%s], port [%u]...\n", __FUNCTION__, host, port);

#if defined(darwin) || defined(__APPLE__) || defined(MACOSX)
	unsigned char *resolv_ip;

	/* Get the DNS servers from the resolv.conf file */
	get_dns_servers();

	//Get the hostname from the terminal
	//printf("Enter Hostname to Lookup : ");
	//scanf("%s" , hostname);
	
	//Now get the ip of this hostname , A record
	//strcpy(resolv_ip, ngethostbyname(host , T_A));
	resolv_ip = ngethostbyname(host , T_A);
	nvram_set("resolv_ip", resolv_ip);
	fprintf(stderr, "%s\n", nvram_safe_get("resolv_ip"));
	{
		//memset(resolv_ip, ngethostbyname(host , T_A), sizeof(ngethostbyname(host , T_A)));
		//resolv_ip = nvram_safe_get("wan0_dns");
		ipaddr = IP_HEX(resolv_ip);
		fprintf(stderr, "My IP Address (0x%x) is %d.%d.%d.%d\n", ip_addr, IP_QUAD(ip_addr));
		//ipaddr = (ip[0] << 24) |(ip[1] << 16) |(ip[2] << 8) |ip[3]);
		//fprintf(stderr, "ipaddr = %d.%d.%d.%d\n", ipaddr>>24, (ipaddr>>16)&0xff, (ipaddr>>8)&0xff, ipaddr&0xff);
	}
	if (!inet_aton(host, &sin.sin_addr) )
	{
		sin.sin_addr.s_addr = inet_addr(resolv_ip);
		if (sin.sin_addr.s_addr == 0) {
				printf("Can't resovle the host : %s IP!\n", host);
				return 0;
		}
		printf("\nHost: %s, Inet: %s\n", host, inet_ntoa(sin.sin_addr));
	}
#else
	if (!inet_aton(host, &sin.sin_addr) )
	{
		step=1; //for dns lookup
		sin.sin_addr.s_addr = resolve_dns(host, 0);
		if (sin.sin_addr.s_addr == 0) {
				fprintf(stderr, "Can't resovle the host : %s IP!\n", host);
				return 0;
		}
		printf("\nHost: %s, Inet: %s\n", host, inet_ntoa(sin.sin_addr));
	}
#endif
 
	return 0;
}

#endif
