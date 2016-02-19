/*
 * gethostinfo.h
 *
 * Created by Jackie Xie on 2011-07-18.
 * Copyright 2011 Jackie Xie. All rights reserved.
 *
 */
#ifndef _GETHOSTINFO_H
#define _GETHOSTINFO_H

#include <pthread.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/* Thread safe DNS lookups */
/*
 *	FIXME: There are some systems that use the same hostent
 *	structure to return for gethostbyname(), if that is the
 *	case then use only one mutex instead of separate mutexes
 */
static int fr_hostbyname = 0;
static pthread_mutex_t fr_hostbyname_mutex;
static pthread_mutex_t fr_hostbyaddr_mutex;

extern int gethostbyname_r(const char *hostname,
               struct hostent *ret, char *buffer, size_t buflen,
               struct hostent **hp, int *error);

#endif