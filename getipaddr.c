/***** getipaddr.c ******/
// $ gcc  -g  getipaddr.c  -o  getipaddr
// $ ./getipaddr   www.yahoo.com
/**** a hostname lookup program example ******/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
 
int main(int argc, char *argv[ ])
{
	struct hostent *h;
	 
	/* error check the command line */
	if(argc != 2)
	{
	    fprintf(stderr, "Usage: %s <domain_name>\n", argv[0]);
	    exit(1);
	}
	 
	/* get the host info */
	if((h=gethostbyname(argv[1])) == NULL)
	{
	    herror("gethostbyname(): ");
	    exit(1);
	}
	else
	    printf("gethostbyname() is OK.\n");
	 
	printf("The host name is: %s\n", h->h_name);
	printf("The IP Address is: %s\n", inet_ntoa(*((struct in_addr *)h->h_addr)));
	printf("The address length is: %d\n", h->h_length);
	 
	printf("Sniffing other names...sniff...sniff...sniff...\n");
	int j = 0;
	do
	{
	    printf("An alias #%d is: %s\n", j, h->h_aliases[j]);
	    j++;
	}
	while(h->h_aliases[j] != NULL);
	 
	printf("Sniffing other IPs...sniff....sniff...sniff...\n");
	int i = 0;
	do
	{
	    printf("Address #%i is: %s\n", i, inet_ntoa(*((struct in_addr *)(h->h_addr_list[i]))));
	    i++;
	}
	while(h->h_addr_list[i] != NULL);
	return 0;
}
