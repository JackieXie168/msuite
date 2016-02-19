/* portscan.c */

/* todo: non-blocking connect + select ? */
/* bugs: empty hostname () */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void usage(void);
int testport(struct sockaddr_in *, char *, int);
int getbanner(int, char *, int);
void printport(int, char *);
void printbanner(int, char *);
void sighdlr(int);

int bflag, lflag;
FILE *logfile;

int
main(int argc, char *argv[])
{
	extern int bflag, lflag;
	extern  FILE *logfile;

	int aflag, ch, port;
	char ip[INET_ADDRSTRLEN], bbuf[48];
	struct hostent *hp;
	struct servent sp;
	struct servent_data sd;
	struct sockaddr_in addr;

	signal(SIGALRM, sighdlr);

	aflag = bflag = lflag = 0;
	while ((ch = getopt(argc, argv, "abl:")) != -1) {
		switch (ch) {
		case 'a':
			aflag++;
			break;
		case 'b':
			bflag++;
			break;
		case 'l':
			lflag++;
			if ((logfile = fopen(optarg, "w")) == NULL) {
				lflag--;
				warn("fopen");
			}
			break;
		default:
			usage();
		}
	}
	argc -=optind;
	argv += optind;

	if (argc < 1)
		usage();

	if ((hp = gethostbyname(*argv)) == NULL)
		errx(1, "gethostbyname: %s", hstrerror(h_errno));

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr, *hp->h_addr_list, sizeof(struct in_addr));

	hp = gethostbyaddr(&addr.sin_addr, sizeof(struct in_addr),
	    AF_INET);

	if (inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip)) == NULL)
		warn("inet_ntop");

	printf("\nPortscanning %s (%s)\n\n", ip, hp ? hp->h_name : "");
	if (lflag)
		fprintf(logfile, "\nPortscanning %s (%s)\n\n", ip, hp ? hp->h_name : "");

	if (aflag) {
		for (port = 1; port <= 65535; port++) {
			addr.sin_port = htons(port);

			if (testport(&addr, bbuf, sizeof(bbuf)) == 0)
				printport(addr.sin_port, bbuf);
		}
	}

	if (!aflag) {
		bzero(&sd, sizeof(sd));
		while (getservent_r(&sp, &sd) != -1) {
			if (strcmp(sp.s_proto, "tcp"))
				continue;

			addr.sin_port = sp.s_port;

			if (testport(&addr, bbuf, sizeof(bbuf)) == 0)
				printport(addr.sin_port, bbuf);
		}
	}

	printf("\n");

	if (lflag) {
		fprintf(logfile, "\n");
		fclose(logfile);
	}

	return 0;
}

void
usage(void)
{
	extern char *__progname;

	fprintf(stdout, "usage: %s [-ab] [-l logfile] <hostname>\n", __progname);
	exit(1);
}

int
testport(struct sockaddr_in *addr, char *bbuf, int blen)
{
	extern int bflag;

	int sockfd, ret;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		warn("socket");
		return -1;
	}

	alarm(1);
	ret = connect(sockfd, (struct sockaddr *)addr, sizeof(struct sockaddr));

	if (ret < 0 && errno == EINTR) {
		close(sockfd);
		return ret;
	}

	if (ret < 0 && errno != ECONNREFUSED) {
		warn("connect");
		close(sockfd);
		return ret;
	}

	if (bflag)
		getbanner(sockfd, bbuf, blen);

	close(sockfd);

	return ret;
}

int
getbanner(int sockfd, char *bbuf, int blen)
{
	ssize_t n;
	fd_set rset;
	struct timeval tv;

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if (select(sockfd+1, &rset, NULL, NULL, &tv) < 1)
		return -1;

	if ((n = read(sockfd, bbuf, blen)) < 0)
		return -1;

	bbuf[n] = '\0';

	return 1;
}

void
printport(int port, char *bbuf)
{
	extern int bflag, lflag;
	extern FILE *logfile;

	struct servent *sp;

	sp = getservbyport(port, "tcp");

	printf("%d", ntohs(port));

	if (sp)
		printf("/%s", sp->s_name);

	if (bflag && strlen(bbuf) > 0)
		printbanner(0, bbuf);

	printf("\n");


	if (lflag) {
		fprintf(logfile, "%d", ntohs(port));

		if (sp)
			fprintf(logfile, "/%s", sp->s_name);

		if (bflag && bbuf)
			printbanner(1, bbuf);

		fprintf(logfile, "\n");

	}
}

void
printbanner(int lflag, char *bbuf)
{
	extern FILE *logfile;
	
	int i;

	if (lflag) {
		fprintf(logfile, " (");
		for (i = 0; i < strlen(bbuf); i++)
			if (bbuf[i] == '\r')
				fprintf(logfile, "\\r");
			else if (bbuf[i] == '\n')
				fprintf(logfile, "\\n");
			else if (isprint(bbuf[i]))
				fprintf(logfile, "%c", bbuf[i]);

		fprintf(logfile, ")");
	} else {
		printf(" (");
		for (i = 0; i < strlen(bbuf); i++)
			if (bbuf[i] == '\r')
				printf("\\r");
			else if (bbuf[i] == '\n')
				printf("\\n");
			else if (isprint(bbuf[i]))
				printf("%c", bbuf[i]);

		printf(")");
	}
}

void
sighdlr(int signo)
{
	return;
}