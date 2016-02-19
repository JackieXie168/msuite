#include <netdb.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(MACOSX) || defined(darwin)
#include "gethostinfo.h"
#endif

#define DUMP(...)   printf(__VA_ARGS__)
int main(int argc,char** argv)
{
	char    buf[1024];
	struct  hostent hostinfo,*phost;
	int	ret;

	DUMP("argc:%d\n",argc);
	if(argc <2 ){
	    printf("ERROR:test domainname\n");
	    return 1;
	}

	if(gethostbyname_r(argv[1],&hostinfo,buf,sizeof(buf),&phost,&ret))
	    printf("ERROR:gethostbyname(%s) ret:%d\n",argv[1],ret);
	else{
	    int i;
	  	printf("gethostbyname(%s) success:ret:%d,",argv[1],ret);
	    if(phost)
		   printf("phost:name:%s,addrtype:%d(AF_INET:%d),len:%d,addr[0]:%s,[1]:%s\n",	   
				 phost->h_name,phost->h_addrtype,AF_INET,
				 phost->h_length,
				 phost->h_addr_list[0],
				 phost->h_addr_list[0] == NULL?0:phost->h_addr_list[1]);
	    for(i = 0;hostinfo.h_aliases[i];i++)
		   printf("host alias is:%s\n",hostinfo.h_aliases[i]);
#if __linux__
	    for(i = 0;hostinfo.h_addr_list[i];i++)
		   printf("host addr is:%s\n",inet_ntoa(*(struct in_addr*)hostinfo.h_addr_list[i]));
#elif defined(__FreeBSD__) || defined(__APPLE__) || defined(MACOSX) || defined(darwin)
		struct in_addr *remoteInAddr;
		char *sRemoteInAddr;
		for (i = 0;hostinfo.h_addr_list[i];i++){
			remoteInAddr = (struct in_addr *) hostinfo.h_addr_list[i];
			sRemoteInAddr = inet_ntoa(*remoteInAddr);
			printf("host addr is:%s\n", sRemoteInAddr);
		}
#endif
	}

	return 0;
}
