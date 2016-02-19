/*
 * gethostinfo.c
 *
 * Created by Jackie Xie on 2011-07-18.
 * Copyright 2011 Jackie Xie. All rights reserved.
 *
 */

#include "gethostinfo.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>

/*
 * gethostbyname() return hostent structure
 * To make these functions thread safe, we need to
 * copy the data and not pointers
 *
 * struct hostent {
 *    char    *h_name;        * official name of host *
 *    char    **h_aliases;    * alias list *
 *    int     h_addrtype;     * host address type *
 *    int     h_length;       * length of address *
 *    char    **h_addr_list;  * list of addresses *
 * }
 * This struct contains 3 pointers as members.
 * The data from these pointers is copied into a buffer.
 * The buffer is formatted as below to store the data
 *  ---------------------------------------------------------------
 * | h_name\0alias_array\0h_aliases\0..\0addr_array\0h_addr_list\0 |
 *  ---------------------------------------------------------------
 */

#define BUFFER_OVERFLOW 255
static int copy_hostent(struct hostent *from, struct hostent *to,
			char *buffer, int buflen, int *error)
{
    int i, len;
    char *ptr = buffer;

    *error = 0;
    to->h_addrtype = from->h_addrtype;
    to->h_length = from->h_length;
    to->h_name = (char *)ptr;

    /* copy hostname to buffer */
    len=strlen(from->h_name)+1;
    strcpy(ptr, from->h_name);
    ptr += len;

    /* copy aliases to buffer */
    to->h_aliases = (char**)ptr;
    for(i = 0; from->h_aliases[i]; i++);
    ptr += (i+1) * sizeof(char *);

    for(i = 0; from->h_aliases[i]; i++) {
       len = strlen(from->h_aliases[i])+1;
       if ((ptr-buffer)+len < buflen) {
           to->h_aliases[i] = ptr;
	       strcpy(ptr, from->h_aliases[i]);
           ptr += len;
       } else {
           *error = BUFFER_OVERFLOW;
           return *error;
       }
    }
    to->h_aliases[i] = NULL;

    /* copy addr_list to buffer */
    to->h_addr_list = (char**)ptr;
    for(i = 0; (int *)from->h_addr_list[i] != 0; i++);
    ptr += (i+1) * sizeof(int *);

    for(i = 0; (int *)from->h_addr_list[i] != 0; i++) {
       len = sizeof(int);
       if ((ptr-buffer)+len < buflen) {
           to->h_addr_list[i] = ptr;
           memcpy(ptr, from->h_addr_list[i], len);
           ptr += len;
       } else {
           *error = BUFFER_OVERFLOW;
            return *error;
       }
    }
    to->h_addr_list[i] = 0;
    return *error;
}

static struct hostent * _gethostbyname_r(const char *hostname, struct hostent 
*result, char *buffer, int buflen, int *error)
{
    struct hostent *hp;

    if (fr_hostbyname == 0) {
    	pthread_mutex_init(&fr_hostbyname_mutex, NULL);
	fr_hostbyname = 1;
    }
    pthread_mutex_lock(&fr_hostbyname_mutex);

    hp = gethostbyname(hostname);
    if ((!hp) || (hp->h_addrtype != AF_INET) || (hp->h_length != 4)) {
	 *error = h_errno;
         hp = NULL;
    } else {
         copy_hostent(hp, result, buffer, buflen, error);
         hp = result;
    }

    pthread_mutex_unlock(&fr_hostbyname_mutex);

    return hp;
}

int gethostbyname_r(const char *hostname,
               struct hostent *ret, char *buffer, size_t buflen,
               struct hostent **hp, int *error)
{
	*hp = _gethostbyname_r(hostname, ret, buffer, buflen, error);
	if(*hp == NULL/* || error == NO_ADDRESS || error == HOST_NOT_FOUND || error == NO_DATA*/)
		return -1;
	else
		return 0;
}
