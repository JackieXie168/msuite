/*
Playing multiplayer starcraft on LAN with multiple subnets

One of the best games of all time must be StarCraft. I recently installed it again, and was delighted to see it now supports UDP instead of the archaic IPX protocol. But this is where the fun started.

My network is divided in to three subnets. I have the WAN connected to the Internet, a Wireless subnet for all my wireless devices (including my one gaming computer), and a LAN for the wired computers (including the game server). But this is where the problem lies - by default UDP broadcasting does not extend subnets - and for a good reason too. However StarCraft uses UDP broadcasting to discover servers to connect to.

Obviously I enabled routing of UDP traffic between the LAN and WiFi subnets, but this was not enough. To have broadcast traffic forwarded to the other subnet, I had to get my hands dirty.

I found this link:http://www.csc.liv.ac.uk/~greg/nfsu2relay.html after a long search. This guy had a similar problem but for a different game - Need For Speed Underground. Since that game operated on the same principals, I took his source code and modified it to support StarCraft. I also modified it to support binding to custom addresses, and to compile on Mac OS X as well as FreeBSD.

After my changes, I now just run this proxy on my gateway where it forwards UDP broadcast traffic between the two interfaces on port 6111, since both client and server sends out broadcasts. As the gateway routes the traffic between both interfaces, by listening on 0.0.0.0 it effectively receives both broadcasts. It does however send the received traffic to a list of StarCraft machines, and does not re-broadcast it as that would create a DoS on the network. I start it like this on the FreeBSD gateway:

./sc-proxy 0.0.0.0 <ip of starcraft client> <ip of starcraft server>

Here is the code. Credit goes to Richard Gregory[http://www.csc.liv.ac.uk/~greg/nfsu2relay.html]. Hope you do not mind!

*/

#ifdef __FreeBSD__
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef unsigned long int n_long;
typedef unsigned short u_short;
typedef unsigned char u_char;
#endif


#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
/*
 Compile with:
 gcc -O2 nfsu2relay.c -o nfsu2relay
 
 For cygwin:
 gcc -O2 nfsu2relay.c -o nfsu2relay -lws2_32 -mno-cygwin
 
 Usage:
 see http://www.csc.liv.ac.uk/~greg/nfsu2relay.html
 
 */


#ifdef __WIN32__
#pragma pack(1)
struct iphdr {
    unsigned char      ihl:4,
version:4;
    unsigned char      tos;
       unsigned short int tot_len;
       unsigned short int id;
       unsigned short int frag_off;
    unsigned char      ttl;
    unsigned char      protocol;
       unsigned short int check;
    unsigned int       saddr;
    unsigned int       daddr;
       /*The options start here. */
};


struct udphdr {
       unsigned short uh_sport;
       unsigned short uh_dport;
       unsigned short uh_ulen;
       unsigned short uh_sum;
};
#else
#include <sys/socket.h>  /* these headers are for a Linux system, but */
#include <netinet/in.h>  /* the names on other systems are easy to guess.. */
#include <netinet/ip.h>
#include <arpa/inet.h>


#define __FAVOR_BSD
/* use bsd'ish udp header */
#include <netinet/udp.h>
#include <unistd.h>
#include <netdb.h>
#endif






unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
       register long    sum;
    u_short oddbyte;
    register u_short answer;
        
    sum = 0;
    while(nbytes > 1)
    {
            sum += *ptr++;
            nbytes -= 2;
    }
        
    if(nbytes == 1)
    {
            oddbyte = 0;
            *((u_char *) &oddbyte) = *(u_char *)ptr;
            sum += oddbyte;
    }
        
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
        
    return(answer);
}


/* define the pseudohdr */


struct pseudohdr {              /* for creating the checksums */
       unsigned long saddr;
       unsigned long daddr;
    char useless;
    unsigned char protocol;
       unsigned short length;
};






ssize_t udpsend(u_int saddr, u_int daddr, unsigned short sport, unsigned short dport, char *data, unsigned short datalen)
{
    struct  sockaddr_in servaddr;
    struct    ip *ipA;
    struct    udphdr *udp;
        
    struct pseudohdr *pseudo;
    char packet[sizeof(struct ip)+sizeof(struct udphdr)+datalen];
    int nbytes, sockfd, on = 1;
        
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0) {
               fprintf(stderr,"cannot create socket - run as root.\n");
               return(0);
    }
        
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (void *)&on, sizeof(on)) == -1) {
               fprintf(stderr, "cannot setsockopt\n");
               return(0);
    }
        
       /*if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST,
     (char *)&on, sizeof(on)) == -1)
     {
     printf("[socket_broadcast] can't set SO_BROADCAST option\n");
     // non fatal error 
     }*/
        
    memset(packet, 0x00, sizeof(packet));
    memcpy(packet+sizeof(struct ip)+sizeof(struct udphdr), data, datalen);
        
    servaddr.sin_addr.s_addr = daddr;
    servaddr.sin_port = htons(dport);
    servaddr.sin_family = AF_INET;
        
    ipA     = (struct ip *)packet;
    udp    = (struct udphdr *)(packet + sizeof(struct ip));
    pseudo = (struct pseudohdr *)(packet + sizeof(struct ip) - sizeof(struct pseudohdr));
        
    udp->uh_sport = htons(sport);
    udp->uh_dport = htons(dport);
    udp->uh_sum = 0;
    udp->uh_ulen = htons(sizeof(struct udphdr)+datalen);
        
    pseudo->saddr    = saddr;
    pseudo->daddr    = daddr;
    pseudo->useless     = 0;
    pseudo->protocol = IPPROTO_UDP;
    pseudo->length   = udp->uh_ulen;
        
    udp->uh_sum = in_cksum((u_short *)pseudo,sizeof(struct udphdr)+sizeof(struct pseudohdr)+datalen); 
        
    struct in_addr saddr1;
    struct in_addr daddr1;
    saddr1.s_addr = saddr;
    daddr1.s_addr = daddr;
    ipA->ip_hl      = 5;
    ipA->ip_v  = 4;
    ipA->ip_tos      = 0x10;
    ipA->ip_len  = sizeof(packet);
    ipA->ip_off = 0;
    ipA->ip_ttl      = 69;
    ipA->ip_p = IPPROTO_UDP;
    ipA->ip_sum    = 0;
    ipA->ip_src    = saddr1;
    ipA->ip_dst    = daddr1;
        
    nbytes = sendto(sockfd, packet, ipA->ip_len, 0, (struct sockaddr *)&servaddr,sizeof(servaddr));
    close(sockfd);
    return(nbytes);
}




void usage(char **argv)
{
       fprintf(stderr,"%s <bind IP> <SC machine ip> <SC machine ip> [SC machine ip...]\n",argv[0]);
       fprintf(stderr,"%s -e <your external ip> <their external ip>\n",argv[0]);
       fprintf(stderr," -e  Modify behaviour to support internet routed NFS2 traffic.\n");
    exit(1);
}


#ifdef __WIN32__
int optind = 1;


char getopt(int argc, char **argv, char *parse) {
    if (optind >= argc)
               return -1;
        
    if (argv[optind][0]=='-') {
            if (!strcmp(argv[optind],"-e")) {
                    optind++;
                       return 'e';
            }
            else {
                    optind++;
                       return '?';
            }
    }
        
       return -1;
}
#endif


int main(int argc, char **argv)
{
    int r;
    char buf[BUFSIZ];
    struct sockaddr_in fromaddr, thisaddr;
    int bindno,s;
    socklen_t fromlen;
        
    char option;
    int opt_usevpn=1;
#ifdef __WIN32__
    WSADATA wsaData;
    WSAStartup(0x0101, &wsaData);
#endif
        
    while( (option=getopt(argc, argv, "e?"))!=-1 )
    {
               //printf("%c %s\n",option, optarg );
            switch( option )
            {
                    case 'e':
                            opt_usevpn=0;
                            break;
                    case ':':  case '?':
                            usage(argv);
                            break;
            };
    }
        
       //printf("optind=%d, opt_usevpn=%d\n",optind, opt_usevpn );
        
    if( (opt_usevpn && argc-optind<3) || (!opt_usevpn && argc!=optind+3) )
            usage(argv);
        
    memset(&thisaddr, 0, sizeof(struct sockaddr_in));
    thisaddr.sin_family =AF_INET;
    thisaddr.sin_addr.s_addr=inet_addr(argv[1]); // INADDR_ANY;
       //   thisaddr.sin_addr.s_addr=inet_addr("255.255.255.255"); (fails to work on cygwin)
    thisaddr.sin_port=htons(6111);
        
    s=socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if( s<0 )
    {
               fprintf(stderr,"socket() failed %d\n",s);
            perror("");
#ifdef __WIN32__
            WSACleanup();
#endif
               return 0;
    }
        
       /* Wait for response */
    if( (bindno = bind(s, (struct sockaddr *)&thisaddr, sizeof(thisaddr) ) ) < 0 )
    {
            fprintf(stderr,"%s: errno = %d ", argv[0], errno);  perror("");
               fprintf(stderr,"%s: can't bind local address\n", argv[0]);
            perror("");
#ifdef __WIN32__
            WSACleanup();
#endif
               return 2;
    }
        
       while(1)
    {
            long packetsize=0;
            int i;
            time_t t;
            time(&t);
                
            fromlen=sizeof(fromaddr);
            r=recvfrom(s, buf,  BUFSIZ, 0, (struct sockaddr *)&fromaddr, &fromlen );
            if( r<0 )
            {
                    fprintf(stderr,"recvfrom=%d\n", r );
                    perror("");
                       continue;
            }
                
            packetsize=r;
                
            printf("%d %s %d %ld %s",t, inet_ntoa(fromaddr.sin_addr), fromaddr.sin_port, packetsize, ctime(&t) );
            fflush(stdout);
                
            for(i=optind+1;i<argc;i++)
            {
                    if( inet_addr(argv[i])!=fromaddr.sin_addr.s_addr )
                    {
                            if( opt_usevpn )
                                    r=udpsend(fromaddr.sin_addr.s_addr, inet_addr (argv[i]), 6111, 6111, buf, packetsize);
                            else
                                    r=udpsend(inet_addr (argv[2]), inet_addr (argv[i]), 6111, 6111, buf, packetsize);
                            if(r<0)
                            {
                                    fprintf(stderr,"send failed, sending %ld bytes from %s to %s.\n", packetsize, opt_usevpn?inet_ntoa(fromaddr.sin_addr):argv[1], argv[i] );
                                       fprintf(stderr,"This probably means the destination ip was invalid.\n");
                                    perror("udpsend()");
#ifdef __WIN32__
                                    WSACleanup();
#endif
                                    exit(0);
                            }   
                    }
               } // for each argument ip address
    } // while always
        
    close(s);
        
#ifdef __WIN32__
    WSACleanup();
#endif
        
       return 0;
}
