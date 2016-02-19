/* vi: set sw=4 ts=4: */
/*
 * wget - retrieve a file using HTTP or FTP
 *
 * Chip Rosenthal Covad Communications <chip@laserlink.net>
 *
 */

#include <netinet/in.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netdb.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>
#include <sys/syscall.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
//#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <limits.h>
#include <sys/param.h>

#define wget_full_usage "\n\n" \
       "Retrieve files via HTTP or FTP\n" \
     "\nOptions:" \
     "\n	-s	Spider mode - only check file existence" \
     "\n	-c	Continue retrieval of aborted transfer" \
     "\n	-q	Quiet" \
     "\n	-P	Set directory prefix to DIR" \
     "\n	-O	Save to filename ('-' for stdout)" \
     "\n	-U	Adjust 'User-Agent' field" \
     "\n	-Y	Use proxy ('on' or 'off')" \

#define LONE_DASH(s)     ((s)[0] == '-' && !(s)[1])

/*#define FAST_FUNC __attribute__((regparm(3),stdcall))*/
#define FAST_FUNC

#define EXTERNALLY_VISIBLE __attribute__(( visibility("default") ))
#ifndef __NR_clock_gettime
# define __NR_timer_create      259
# define __NR_clock_gettime     (__NR_timer_create+6)
#endif

#define DEPRECATED __attribute__ ((__deprecated__))
#define UNUSED_PARAM_RESULT __attribute__ ((warn_unused_result))

/* We need to export XXX_main from libbusybox
 * only if we build "individual" binaries
 */
#if ENABLE_FEATURE_INDIVIDUAL
#define MAIN_EXTERNALLY_VISIBLE EXTERNALLY_VISIBLE
#else
#define MAIN_EXTERNALLY_VISIBLE
#endif

#define UNUSED_PARAM __attribute__ ((__unused__))
#define NORETURN __attribute__ ((__noreturn__))
#define PACKED __attribute__ ((__packed__))
#define ALIGNED(m) __attribute__ ((__aligned__(m)))
/*#define COMMON_BUFSIZE 6*/
#define ENABLE_FEATURE_CLEAN_UP 0
#define ENABLE_FEATURE_WGET_STATUSBAR 1
#define ENABLE_FEATURE_WGET_AUTHENTICATION 1
#define ENABLE_FEATURE_WGET_LONG_OPTIONS 0
#define USE_FEATURE_WGET_LONG_OPTIONS(...)
#define SKIP_FEATURE_WGET_LONG_OPTIONS(...) __VA_ARGS__
#define ENABLE_FEATURE_SYSLOG 1
#define ENABLE_FEATURE_PREFER_APPLETS 0
#define ENABLE_FEATURE_IPV6 1
#define ENABLE_HUSH 0
#define ALWAYS_INLINE inline /* n/a */
#define ALIGN1 __attribute__((aligned(1)))
#define ALIGN2 __attribute__((aligned(2)))
#define bb_msg_memory_exhausted "memory exhausted"

/* This one is more efficient - we save ~400 bytes */
#undef isdigit
#define isdigit(a) ((unsigned)((a) - '0') <= 9)
#undef isspace
#undef isprint
#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))
#define isprint(c) (((unsigned int)((c) - 0x20)) <= (0x7e - 0x20))

typedef signed char smallint;
typedef unsigned char smalluint;

/* ISO C Standard:  7.16  Boolean type and values  <stdbool.h> */
#if (defined __digital__ && defined __unix__)
/* old system without (proper) C99 support */
#define bool smalluint
#else
/* modern system, so use it */
#include <stdbool.h>
#endif

#ifndef BUFSIZ
#define BUFSIZ 4096
#endif
/* Providing hard guarantee on minimum size (think of BUFSIZ == 128) */
enum { COMMON_BUFSIZE = (BUFSIZ >= 256*sizeof(void*) ? BUFSIZ+1 : 256*sizeof(void*)) };

/* We use it for "global" data via *(struct global*)&bb_common_bufsiz1.
 * Since gcc insists on aligning struct global's members, it would be a pity
 * (and an alignment fault on some CPUs) to mess it up. */
char bb_common_bufsiz1[COMMON_BUFSIZE] ALIGNED(sizeof(long long));
const char bb_msg_read_error[] ALIGN1 = "read error";

/* Conversion table.  for base 64 */
const char bb_uuenc_tbl_base64[65 + 2] ALIGN1 = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/',
	'=' /* termination character */,
	'\n', '\0' /* needed for uudecode.c */
};

const char bb_uuenc_tbl_std[65] ALIGN1 = {
	'`', '!', '"', '#', '$', '%', '&', '\'',
	'(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ':', ';', '<', '=', '>', '?',
	'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
	'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
	'`' /* termination character */
};

enum {
	LOGMODE_NONE = 0,
	LOGMODE_STDIO = (1 << 0),
	LOGMODE_SYSLOG = (1 << 1) * ENABLE_FEATURE_SYSLOG,
	LOGMODE_BOTH = LOGMODE_SYSLOG + LOGMODE_STDIO
};

typedef struct len_and_sockaddr {
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
		struct sockaddr_in6 sin6;
#endif
	} u;
} len_and_sockaddr;

enum {
	LSA_LEN_SIZE = offsetof(len_and_sockaddr, u),
	LSA_SIZEOF_SA = sizeof(
		union {
			struct sockaddr sa;
			struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
			struct sockaddr_in6 sin6;
#endif
		}
	)
};


struct host_info {
	// May be used if we ever will want to free() all xstrdup()s...
	/* char *allocated; */
	const char *path;
	const char *user;
	char       *host;
	int         port;
	smallint    is_ftp;
};


/* Globals (can be accessed from signal handlers) */
struct globals {
	off_t content_len;        /* Content-length of the file */
	off_t beg_range;          /* Range at which continue begins */
#if ENABLE_FEATURE_WGET_STATUSBAR
	off_t lastsize;
	off_t totalsize;
	off_t transferred;        /* Number of bytes transferred so far */
	const char *curfile;      /* Name of current file being transferred */
	unsigned lastupdate_sec;
	unsigned start_sec;
#endif
	smallint chunked;             /* chunked transfer encoding */
};
#define G (*(struct globals*)&bb_common_bufsiz1)
struct BUG_G_too_big {
	char BUG_G_too_big[sizeof(G) <= COMMON_BUFSIZE ? 1 : -1];
};
#define content_len     (G.content_len    )
#define beg_range       (G.beg_range      )
#define lastsize        (G.lastsize       )
#define totalsize       (G.totalsize      )
#define transferred     (G.transferred    )
#define curfile         (G.curfile        )
#define lastupdate_sec  (G.lastupdate_sec )
#define start_sec       (G.start_sec      )
#define chunked         (G.chunked        )
#define INIT_G() do { } while (0)

/* Last element is marked by mult == 0 */
struct suffix_mult {
	char suffix[4];
	unsigned mult;
};

int xfunc_error_retval = EXIT_FAILURE;
smallint logmode = LOGMODE_STDIO;
const char *msg_eol = "\n";
int die_sleep;
jmp_buf die_jmp;

void FAST_FUNC bb_verror_msg(const char *s, va_list p, const char* strerr);
void FAST_FUNC bb_error_msg_and_die(const char *s, ...);

#define type long long
#define xstrtou(rest) xstrtoull##rest
#define xstrto(rest) xstrtoll##rest
#define xatou(rest) xatoull##rest
#define xato(rest) xatoll##rest
#define XSTR_UTYPE_MAX ULLONG_MAX
#define XSTR_TYPE_MAX LLONG_MAX
#define XSTR_TYPE_MIN LLONG_MIN
#define XSTR_STRTOU strtoull

#if ULONG_MAX != ULLONG_MAX
#define type long
#define xstrtou(rest) xstrtoul##rest
#define xstrto(rest) xstrtol##rest
#define xatou(rest) xatoul##rest
#define xato(rest) xatol##rest
#define XSTR_UTYPE_MAX ULONG_MAX
#define XSTR_TYPE_MAX LONG_MAX
#define XSTR_TYPE_MIN LONG_MIN
#define XSTR_STRTOU strtoul
#endif

#if UINT_MAX != ULONG_MAX
static ALWAYS_INLINE
unsigned bb_strtoui(const char *str, char **end, int b)
{
	unsigned long v = strtoul(str, end, b);
	if (v > UINT_MAX) {
		errno = ERANGE;
		return UINT_MAX;
	}
	return v;
}
#define type int
#define xstrtou(rest) xstrtou##rest
#define xstrto(rest) xstrtoi##rest
#define xatou(rest) xatou##rest
#define xato(rest) xatoi##rest
#define XSTR_UTYPE_MAX UINT_MAX
#define XSTR_TYPE_MAX INT_MAX
#define XSTR_TYPE_MIN INT_MIN
/* libc has no strtoui, so we need to create/use our own */
#define XSTR_STRTOU bb_strtoui
#endif


unsigned type FAST_FUNC xstrtou(_range_sfx)(const char *numstr, int base,
		unsigned type lower,
		unsigned type upper,
		const struct suffix_mult *suffixes)
{
	unsigned type r;
	int old_errno;
	char *e;

	/* Disallow '-' and any leading whitespace. Make sure we get the
	 * actual isspace function rather than a macro implementaion. */
	if (*numstr == '-' || *numstr == '+' || (isspace)(*numstr))
		goto inval;

	/* Since this is a lib function, we're not allowed to reset errno to 0.
	 * Doing so could break an app that is deferring checking of errno.
	 * So, save the old value so that we can restore it if successful. */
	old_errno = errno;
	errno = 0;
	r = XSTR_STRTOU(numstr, &e, base);
	/* Do the initial validity check.  Note: The standards do not
	 * guarantee that errno is set if no digits were found.  So we
	 * must test for this explicitly. */
	if (errno || numstr == e)
		goto inval; /* error / no digits / illegal trailing chars */

	errno = old_errno;	/* Ok.  So restore errno. */

	/* Do optional suffix parsing.  Allow 'empty' suffix tables.
	 * Note that we also allow nul suffixes with associated multipliers,
	 * to allow for scaling of the numstr by some default multiplier. */
	if (suffixes) {
		while (suffixes->mult) {
			if (strcmp(suffixes->suffix, e) == 0) {
				if (XSTR_UTYPE_MAX / suffixes->mult < r)
					goto range; /* overflow! */
				r *= suffixes->mult;
				goto chk_range;
			}
			++suffixes;
		}
	}

	/* Note: trailing space is an error.
	   It would be easy enough to allow though if desired. */
	if (*e)
		goto inval;
 chk_range:
	/* Finally, check for range limits. */
	if (r >= lower && r <= upper)
		return r;
 range:
	bb_error_msg_and_die("number %s is not in %llu..%llu range",
		numstr, (unsigned long long)lower,
		(unsigned long long)upper);
 inval:
	bb_error_msg_and_die("invalid number '%s'", numstr);
}

unsigned type FAST_FUNC xstrtou(_range)(const char *numstr, int base,
		unsigned type lower,
		unsigned type upper)
{
	return xstrtou(_range_sfx)(numstr, base, lower, upper, NULL);
}

unsigned type FAST_FUNC xstrtou(_sfx)(const char *numstr, int base,
		const struct suffix_mult *suffixes)
{
	return xstrtou(_range_sfx)(numstr, base, 0, XSTR_UTYPE_MAX, suffixes);
}

unsigned type FAST_FUNC xstrtou()(const char *numstr, int base)
{
	return xstrtou(_range_sfx)(numstr, base, 0, XSTR_UTYPE_MAX, NULL);
}

unsigned type FAST_FUNC xatou(_range_sfx)(const char *numstr,
		unsigned type lower,
		unsigned type upper,
		const struct suffix_mult *suffixes)
{
	return xstrtou(_range_sfx)(numstr, 10, lower, upper, suffixes);
}

unsigned type FAST_FUNC xatou(_range)(const char *numstr,
		unsigned type lower,
		unsigned type upper)
{
	return xstrtou(_range_sfx)(numstr, 10, lower, upper, NULL);
}

unsigned type FAST_FUNC xatou(_sfx)(const char *numstr,
		const struct suffix_mult *suffixes)
{
	return xstrtou(_range_sfx)(numstr, 10, 0, XSTR_UTYPE_MAX, suffixes);
}

unsigned type FAST_FUNC xatou()(const char *numstr)
{
	return xatou(_sfx)(numstr, NULL);
}

/* Signed ones */

type FAST_FUNC xstrto(_range_sfx)(const char *numstr, int base,
		type lower,
		type upper,
		const struct suffix_mult *suffixes)
{
	unsigned type u = XSTR_TYPE_MAX;
	type r;
	const char *p = numstr;

	/* NB: if you'll decide to disallow '+':
	 * at least renice applet needs to allow it */
	if (p[0] == '+' || p[0] == '-') {
		++p;
		if (p[0] == '-')
			++u; /* = <type>_MIN (01111... + 1 == 10000...) */
	}

	r = xstrtou(_range_sfx)(p, base, 0, u, suffixes);

	if (*numstr == '-') {
		r = -r;
	}

	if (r < lower || r > upper) {
		bb_error_msg_and_die("number %s is not in %lld..%lld range",
				numstr, (long long)lower, (long long)upper);
	}

	return r;
}

type FAST_FUNC xstrto(_range)(const char *numstr, int base, type lower, type upper)
{
	return xstrto(_range_sfx)(numstr, base, lower, upper, NULL);
}

type FAST_FUNC xato(_range_sfx)(const char *numstr,
		type lower,
		type upper,
		const struct suffix_mult *suffixes)
{
	return xstrto(_range_sfx)(numstr, 10, lower, upper, suffixes);
}

type FAST_FUNC xato(_range)(const char *numstr, type lower, type upper)
{
	return xstrto(_range_sfx)(numstr, 10, lower, upper, NULL);
}

type FAST_FUNC xato(_sfx)(const char *numstr, const struct suffix_mult *suffixes)
{
	return xstrto(_range_sfx)(numstr, 10, XSTR_TYPE_MIN, XSTR_TYPE_MAX, suffixes);
}

type FAST_FUNC xato()(const char *numstr)
{
	return xstrto(_range_sfx)(numstr, 10, XSTR_TYPE_MIN, XSTR_TYPE_MAX, NULL);
}

#undef type
#undef xstrtou
#undef xstrto
#undef xatou
#undef xato
#undef XSTR_UTYPE_MAX
#undef XSTR_TYPE_MAX
#undef XSTR_TYPE_MIN
#undef XSTR_STRTOU

/* A few special cases */

int FAST_FUNC xatoi_u(const char *numstr)
{
	return xatou_range(numstr, 0, INT_MAX);
}

uint16_t FAST_FUNC xatou16(const char *numstr)
{
	return xatou_range(numstr, 0, 0xffff);
}


/* Large file support */
/* Note that CONFIG_LFS=y forces bbox to be built with all common ops
 * (stat, lseek etc) mapped to "largefile" variants by libc.
 * Practically it means that open() automatically has O_LARGEFILE added
 * and all filesize/file_offset parameters and struct members are "large"
 * (in today's world - signed 64bit). For full support of large files,
 * we need a few helper #defines (below) and careful use of off_t
 * instead of int/ssize_t. No lseek64(), O_LARGEFILE etc necessary */
#if ENABLE_LFS
/* CONFIG_LFS is on */
# if ULONG_MAX > 0xffffffff
/* "long" is long enough on this system */
#  define XATOOFF(a) xatoul_range(a, 0, LONG_MAX)
/* usage: sz = BB_STRTOOFF(s, NULL, 10); if (errno || sz < 0) die(); */
#  define BB_STRTOOFF bb_strtoul
#  define STRTOOFF strtoul
/* usage: printf("size: %"OFF_FMT"d (%"OFF_FMT"x)\n", sz, sz); */
#  define OFF_FMT "l"
# else
/* "long" is too short, need "long long" */
#  define XATOOFF(a) xatoull_range(a, 0, LLONG_MAX)
#  define BB_STRTOOFF bb_strtoull
#  define STRTOOFF strtoull
#  define OFF_FMT "ll"
# endif
#else
/* CONFIG_LFS is off */
# if UINT_MAX == 0xffffffff
/* While sizeof(off_t) == sizeof(int), off_t is typedef'ed to long anyway.
 * gcc will throw warnings on printf("%d", off_t). Crap... */
#  define XATOOFF(a) xatoi_u(a)
#  define BB_STRTOOFF bb_strtou
#  define STRTOOFF strtol
#  define OFF_FMT "l"
# else
#  define XATOOFF(a) xatoul_range(a, 0, LONG_MAX)
#  define BB_STRTOOFF bb_strtoul
#  define STRTOOFF strtol
#  define OFF_FMT "l"
# endif
#endif
/* scary. better ideas? (but do *test* them first!) */
#define OFF_T_MAX  ((off_t)~((off_t)1 << (sizeof(off_t)*8-1)))

/* Like strncpy but make sure the resulting string is always 0 terminated. */
char* FAST_FUNC safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size) return dst;
	dst[--size] = '\0';
	return strncpy(dst, src, size);
}

ssize_t FAST_FUNC safe_write(int fd, const void *buf, size_t count)
{
	ssize_t n;

	do {
		n = write(fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

/*
 * Write all of the supplied buffer out to a file.
 * This does multiple writes as necessary.
 * Returns the amount written, or -1 on an error.
 */
ssize_t FAST_FUNC full_write(int fd, const void *buf, size_t len)
{
	ssize_t cc;
	ssize_t total;

	total = 0;

	while (len) {
		cc = safe_write(fd, buf, len);

		if (cc < 0) {
			if (total) {
				/* we already wrote some! */
				/* user can do another write to know the error code */
				return total;
			}
			return cc;	/* write() returns -1 on failure. */
		}

		total += cc;
		buf = ((const char *)buf) + cc;
		len -= cc;
	}

	return total;
}

void FAST_FUNC xfunc_die(void)
{
	if (die_sleep) {
		if ((ENABLE_FEATURE_PREFER_APPLETS || ENABLE_HUSH)
		 && die_sleep < 0
		) {
			/* Special case. We arrive here if NOFORK applet
			 * calls xfunc, which then decides to die.
			 * We don't die, but jump instead back to caller.
			 * NOFORK applets still cannot carelessly call xfuncs:
			 * p = xmalloc(10);
			 * q = xmalloc(10); // BUG! if this dies, we leak p!
			 */
			/* -2222 means "zero" (longjmp can't pass 0)
			 * run_nofork_applet() catches -2222. */
			longjmp(die_jmp, xfunc_error_retval ? xfunc_error_retval : -2222);
		}
		sleep(die_sleep);
	}
	exit(xfunc_error_retval);
}

#ifndef DMALLOC
/* dmalloc provides variants of these that do abort() on failure.
 * Since dmalloc's prototypes overwrite the impls here as they are
 * included after these prototypes in libbb.h, all is well.
 */
// Warn if we can't allocate size bytes of memory.
void* FAST_FUNC malloc_or_warn(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL && size != 0)
		bb_error_msg(bb_msg_memory_exhausted);
	return ptr;
}

// Die if we can't allocate size bytes of memory.
void* FAST_FUNC xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL && size != 0)
		bb_error_msg_and_die(bb_msg_memory_exhausted);
	return ptr;
}

// Die if we can't resize previously allocated memory.  (This returns a pointer
// to the new memory, which may or may not be the same as the old memory.
// It'll copy the contents to a new chunk and free the old one if necessary.)
void* FAST_FUNC xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr == NULL && size != 0)
		bb_error_msg_and_die(bb_msg_memory_exhausted);
	return ptr;
}
#endif /* DMALLOC */

const char *applet_name = "debug stuff usage";
void FAST_FUNC bb_verror_msg(const char *s, va_list p, const char* strerr)
{
	char *msg;
	int applet_len, strerr_len, msgeol_len, used;

	if (!logmode)
		return;

	if (!s) /* nomsg[_and_die] uses NULL fmt */
		s = ""; /* some libc don't like printf(NULL) */

	used = vasprintf(&msg, s, p);
	if (used < 0)
		return;

	/* This is ugly and costs +60 bytes compared to multiple
	 * fprintf's, but is guaranteed to do a single write.
	 * This is needed for e.g. httpd logging, when multiple
	 * children can produce log messages simultaneously. */

	applet_len = strlen(applet_name) + 2; /* "applet: " */
	strerr_len = strerr ? strlen(strerr) : 0;
	msgeol_len = strlen(msg_eol);
	/* +3 is for ": " before strerr and for terminating NUL */
	msg = xrealloc(msg, applet_len + used + strerr_len + msgeol_len + 3);
	/* TODO: maybe use writev instead of memmoving? Need full_writev? */
	memmove(msg + applet_len, msg, used);
	used += applet_len;
	strcpy(msg, applet_name);
	msg[applet_len - 2] = ':';
	msg[applet_len - 1] = ' ';
	if (strerr) {
		if (s[0]) { /* not perror_nomsg? */
			msg[used++] = ':';
			msg[used++] = ' ';
		}
		strcpy(&msg[used], strerr);
		used += strerr_len;
	}
	strcpy(&msg[used], msg_eol);

	if (logmode & LOGMODE_STDIO) {
		fflush(stdout);
		full_write(STDERR_FILENO, msg, used + msgeol_len);
	}
	if (logmode & LOGMODE_SYSLOG) {
		syslog(LOG_ERR, "%s", msg + applet_len);
	}
	free(msg);
}

void FAST_FUNC bb_error_msg(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	bb_verror_msg(s, p, NULL);
	va_end(p);
}

void FAST_FUNC bb_error_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	bb_verror_msg(s, p, NULL);
	va_end(p);
	xfunc_die();
}

void FAST_FUNC bb_perror_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	/* Guard against "<error message>: Success" */
	bb_verror_msg(s, p, errno ? strerror(errno) : NULL);
	va_end(p);
	xfunc_die();
}


typedef struct llist_t {
	char *data;
	struct llist_t *link;
} llist_t;

/* Add data to the start of the linked list.  */
void FAST_FUNC llist_add_to(llist_t **old_head, void *data)
{
	llist_t *new_head = xmalloc(sizeof(llist_t));

	new_head->data = data;
	new_head->link = *old_head;
	*old_head = new_head;
}

/* Add data to the end of the linked list.  */
void FAST_FUNC llist_add_to_end(llist_t **list_head, void *data)
{
	llist_t *new_item = xmalloc(sizeof(llist_t));

	new_item->data = data;
	new_item->link = NULL;

	if (!*list_head)
		*list_head = new_item;
	else {
		llist_t *tail = *list_head;

		while (tail->link)
			tail = tail->link;
		tail->link = new_item;
	}
}

/* Remove first element from the list and return it */
void* FAST_FUNC llist_pop(llist_t **head)
{
	void *data, *next;

	if (!*head)
		return NULL;

	data = (*head)->data;
	next = (*head)->link;
	free(*head);
	*head = next;

	return data;
}

/* Unlink arbitrary given element from the list */
void FAST_FUNC llist_unlink(llist_t **head, llist_t *elm)
{
	llist_t *crt;

	if (!(elm && *head))
		return;

	if (elm == *head) {
		*head = (*head)->link;
		return;
	}

	for (crt = *head; crt; crt = crt->link) {
		if (crt->link == elm) {
			crt->link = elm->link;
			return;
		}
	}
}

/* Recursively free all elements in the linked list.  If freeit != NULL
 * call it on each datum in the list */
void FAST_FUNC llist_free(llist_t *elm, void (*freeit) (void *data))
{
	while (elm) {
		void *data = llist_pop(&elm);

		if (freeit)
			freeit(data);
	}
}

#ifdef UNUSED
/* Reverse list order. */
llist_t* FAST_FUNC llist_rev(llist_t *list)
{
	llist_t *rev = NULL;

	while (list) {
		llist_t *next = list->link;

		list->link = rev;
		rev = list;
		list = next;
	}
	return rev;
}
#endif


/* Find out if the last character of a string matches the one given.
 * Don't underrun the buffer if the string length is 0.
 */
char* FAST_FUNC last_char_is(const char *s, int c)
{
	if (s && *s) {
		size_t sz = strlen(s) - 1;
		s += sz;
		if ( (unsigned char)*s == c)
			return (char*)s;
	}
	return NULL;
}

// Die with an error message if we can't malloc() enough space and do an
// sprintf() into that space.
char* FAST_FUNC xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

#if 1
	// GNU extension
	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);
#else
	// Bloat for systems that haven't got the GNU extension.
	va_start(p, format);
	r = vsnprintf(NULL, 0, format, p);
	va_end(p);
	string_ptr = xmalloc(r+1);
	va_start(p, format);
	r = vsnprintf(string_ptr, r+1, format, p);
	va_end(p);
#endif

	if (r < 0)
		bb_error_msg_and_die(bb_msg_memory_exhausted);
	return string_ptr;
}


/*
 * "/"        -> "/"
 * "abc"      -> "abc"
 * "abc/def"  -> "def"
 * "abc/def/" -> ""
 */
char* FAST_FUNC bb_get_last_path_component_nostrip(const char *path)
{
	char *slash = strrchr(path, '/');

	if (!slash || (slash == path && !slash[1]))
		return (char*)path;

	return slash + 1;
}

char* FAST_FUNC concat_path_file(const char *path, const char *filename)
{
	char *lc;

	if (!path)
		path = "";
	lc = last_char_is(path, '/');
	while (*filename == '/')
		filename++;
	return xasprintf("%s%s%s", path, (lc==NULL ? "/" : ""), filename);
}

static unsigned long long ret_ERANGE(void)
{
	errno = ERANGE; /* this ain't as small as it looks (on glibc) */
	return ULLONG_MAX;
}

static unsigned long long handle_errors(unsigned long long v, char **endp, char *endptr)
{
	if (endp) *endp = endptr;

	/* errno is already set to ERANGE by strtoXXX if value overflowed */
	if (endptr[0]) {
		/* "1234abcg" or out-of-range? */
		if (isalnum(endptr[0]) || errno)
			return ret_ERANGE();
		/* good number, just suspicious terminator */
		errno = EINVAL;
	}
	return v;
}

unsigned long long FAST_FUNC bb_strtoull(const char *arg, char **endp, int base)
{
	unsigned long long v;
	char *endptr;

	/* strtoul("  -4200000000") returns 94967296, errno 0 (!) */
	/* I don't think that this is right. Preventing this... */
	if (!isalnum(arg[0])) return ret_ERANGE();

	/* not 100% correct for lib func, but convenient for the caller */
	errno = 0;
	v = strtoull(arg, &endptr, base);
	return handle_errors(v, endp, endptr);
}

unsigned FAST_FUNC bb_strtou(const char *arg, char **endp, int base)
{
	unsigned long v;
	char *endptr;

	if (!isalnum(arg[0])) return ret_ERANGE();
	errno = 0;
	v = strtoul(arg, &endptr, base);
	if (v > UINT_MAX) return ret_ERANGE();
	return handle_errors(v, endp, endptr);
}


/* Saves 2 bytes on x86! Oh my... */
int FAST_FUNC sigaction_set(int signum, const struct sigaction *act)
{
	return sigaction(signum, act, NULL);
}

void FAST_FUNC signal_SA_RESTART_empty_mask(int sig, void (*handler)(int))
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	/*sigemptyset(&sa.sa_mask);*/
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = handler;
	sigaction_set(sig, &sa);
}

/* Old glibc (< 2.3.4) does not provide this constant. We use syscall
 * directly so this definition is safe. 
#ifndef CLOCK_MONOTONIC
#if __linux__
#define CLOCK_MONOTONIC 1
#elif defined(darwin) || defined(__FreeBSD__) || defined(__APPLE__) || defined(MACOSX)
#define CLOCK_MONOTONIC 0
#endif
#endif

#if defined(darwin) || defined(__FreeBSD__) || defined(__APPLE__) || defined(MACOSX)
int clock_gettime(int clk_id, struct timespec* t) {
    struct timeval now;
    int rv = gettimeofday(&now, NULL);
    if (rv) return rv;
    t->tv_sec  = now.tv_sec;
    t->tv_nsec = now.tv_usec * 1000;
    return 0;
}
#endif

*/

#if defined(__MACH__) || defined(darwin) || defined(__FreeBSD__) || defined(__APPLE__) || defined(MACOSX)
#include <mach/mach_time.h>
#ifndef CLOCK_MONOTONIC
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 0
#endif
static void get_mono(struct timespec *ts)
{
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t time;
    time = mach_absolute_time();
    double nseconds = ((double)time * (double)timebase.numer)/((double)timebase.denom);
    double seconds = ((double)time * (double)timebase.numer)/((double)timebase.denom * 1e9);
    ts->tv_sec = seconds;
    ts->tv_nsec = nseconds;
    return 0;
}
#elif __linux__
#include <time.h>
#define CLOCK_MONOTONIC 1

/* libc has incredibly messy way of doing this,
 * typically requiring -lrt. We just skip all this mess */
static void get_mono(struct timespec *ts)
{
	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
		bb_perror_msg_and_die("clock_gettime(MONOTONIC) failed");
}
#endif

unsigned long long FAST_FUNC monotonic_ns(void)
{
	struct timespec ts;
	get_mono(&ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

unsigned long long FAST_FUNC monotonic_us(void)
{
	struct timespec ts;
	get_mono(&ts);
	return ts.tv_sec * 1000000ULL + ts.tv_nsec/1000;
}

unsigned FAST_FUNC monotonic_sec(void)
{
	struct timespec ts;
	get_mono(&ts);
	return ts.tv_sec;
}

// Die if we can't copy a string to freshly allocated memory.
char* FAST_FUNC xstrdup(const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup(s);

	if (t == NULL)
		bb_error_msg_and_die(bb_msg_memory_exhausted);

	return t;
}

char* FAST_FUNC skip_whitespace(const char *s)
{
	/* NB: isspace('\0') returns 0 */
	while (isspace(*s)) ++s;

	return (char *) s;
}

char* FAST_FUNC skip_non_whitespace(const char *s)
{
	while (*s && !isspace(*s)) ++s;

	return (char *) s;
}

/*
 * Encode bytes at S of length LENGTH to uuencode or base64 format and place it
 * to STORE.  STORE will be 0-terminated, and must point to a writable
 * buffer of at least 1+BASE64_LENGTH(length) bytes.
 * where BASE64_LENGTH(len) = (4 * ((LENGTH + 2) / 3))
 */
void FAST_FUNC bb_uuencode(char *p, const void *src, int length, const char *tbl)
{
	const unsigned char *s = src;

	/* Transform the 3x8 bits to 4x6 bits */
	while (length > 0) {
		unsigned s1, s2;

		/* Are s[1], s[2] valid or should be assumed 0? */
		s1 = s2 = 0;
		length -= 3; /* can be >=0, -1, -2 */
		if (length >= -1) {
			s1 = s[1];
			if (length >= 0)
				s2 = s[2];
		}
		*p++ = tbl[s[0] >> 2];
		*p++ = tbl[((s[0] & 3) << 4) + (s1 >> 4)];
		*p++ = tbl[((s1 & 0xf) << 2) + (s2 >> 6)];
		*p++ = tbl[s2 & 0x3f];
		s += 3;
	}
	/* Zero-terminate */
	*p = '\0';
	/* If length is -2 or -1, pad last char or two */
	while (length) {
		*--p = tbl[64];
		length++;
	}
}

/* returns the array index of the string */
/* (index of first match is returned, or -1) */
int FAST_FUNC index_in_str_array(const char *const string_array[], const char *key)
{
	int i;

	for (i = 0; string_array[i] != 0; i++) {
		if (strcmp(string_array[i], key) == 0) {
			return i;
		}
	}
	return -1;
}

int FAST_FUNC index_in_strings(const char *strings, const char *key)
{
	int idx = 0;

	while (*strings) {
		if (strcmp(strings, key) == 0) {
			return idx;
		}
		strings += strlen(strings) + 1; /* skip NUL */
		idx++;
	}
	return -1;
}

/* returns the array index of the string, even if it matches only a beginning */
/* (index of first match is returned, or -1) */
#ifdef UNUSED
int FAST_FUNC index_in_substr_array(const char *const string_array[], const char *key)
{
	int i;
	int len = strlen(key);
	if (len) {
		for (i = 0; string_array[i] != 0; i++) {
			if (strncmp(string_array[i], key, len) == 0) {
				return i;
			}
		}
	}
	return -1;
}
#endif

int FAST_FUNC index_in_substrings(const char *strings, const char *key)
{
	int len = strlen(key);

	if (len) {
		int idx = 0;
		while (*strings) {
			if (strncmp(strings, key, len) == 0) {
				return idx;
			}
			strings += strlen(strings) + 1; /* skip NUL */
			idx++;
		}
	}
	return -1;
}

const char* FAST_FUNC nth_string(const char *strings, int n)
{
	while (n) {
		n--;
		strings += strlen(strings) + 1;
	}
	return strings;
}

void FAST_FUNC set_nport(len_and_sockaddr *lsa, unsigned port)
{
#if ENABLE_FEATURE_IPV6
	if (lsa->u.sa.sa_family == AF_INET6) {
		lsa->u.sin6.sin6_port = port;
		return;
	}
#endif
	if (lsa->u.sa.sa_family == AF_INET) {
		lsa->u.sin.sin_port = port;
		return;
	}
	/* What? UNIX socket? IPX?? :) */
}

// Die if we can't open a file and return a fd.
int FAST_FUNC xopen3(const char *pathname, int flags, int mode)
{
	int ret;

	ret = open(pathname, flags, mode);
	if (ret < 0) {
		bb_perror_msg_and_die("can't open '%s'", pathname);
	}
	return ret;
}

// Die if we can't open an existing file and return a fd.
int FAST_FUNC xopen(const char *pathname, int flags)
{
	return xopen3(pathname, flags, 0666);
}

// Die with an error message if we can't open a new socket.
int FAST_FUNC xsocket(int domain, int types, int protocol)
{
	int r = socket(domain, types, protocol);

	if (r < 0) {
		/* Hijack vaguely related config option */
		bb_perror_msg_and_die("socket");
	}

	return r;
}

void FAST_FUNC xconnect(int s, const struct sockaddr *s_addr, socklen_t addrlen)
{
	if (connect(s, s_addr, addrlen) < 0) {
		if (ENABLE_FEATURE_CLEAN_UP)
			close(s);
		if (s_addr->sa_family == AF_INET)
			bb_perror_msg_and_die("%s (%s)",
				"cannot connect to remote host",
				inet_ntoa(((struct sockaddr_in *)s_addr)->sin_addr));
		bb_perror_msg_and_die("cannot connect to remote host");
	}
}

int FAST_FUNC xconnect_stream(const len_and_sockaddr *lsa)
{
	int fd = xsocket(lsa->u.sa.sa_family, SOCK_STREAM, 0);
	xconnect(fd, &lsa->u.sa, lsa->len);
	return fd;
}

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will add this bit anyway */
#define IGNORE_PORT NI_NUMERICSERV
static char* FAST_FUNC sockaddr2str(const struct sockaddr *sa, int flags)
{
	char host[128];
	char serv[16];
	int rc;
	socklen_t salen;

	salen = LSA_SIZEOF_SA;
#if ENABLE_FEATURE_IPV6
	if (sa->sa_family == AF_INET)
		salen = sizeof(struct sockaddr_in);
	if (sa->sa_family == AF_INET6)
		salen = sizeof(struct sockaddr_in6);
#endif
	rc = getnameinfo(sa, salen,
			host, sizeof(host),
	/* can do ((flags & IGNORE_PORT) ? NULL : serv) but why bother? */
			serv, sizeof(serv),
			/* do not resolve port# into service _name_ */
			flags | NI_NUMERICSERV
	);
	if (rc)
		return NULL;
	if (flags & IGNORE_PORT){
		return xstrdup(host);
	}
#if ENABLE_FEATURE_IPV6
	if (sa->sa_family == AF_INET6) {
		if (strchr(host, ':')) /* heh, it's not a resolved hostname */
			return xasprintf("[%s]:%s", host, serv);
		/*return xasprintf("%s:%s", host, serv);*/
		/* - fall through instead */
	}
#endif
	/* For now we don't support anything else, so it has to be INET */
	/*if (sa->sa_family == AF_INET)*/
		return xasprintf("%s:%s", host, serv);
	/*return xstrdup(host);*/
}

#define USE_FEATURE_IPV6(...) __VA_ARGS__

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will remove this bit anyway */
#define DIE_ON_ERROR AI_CANONNAME

/* host: "1.2.3.4[:port]", "www.google.com[:port]"
 * port: if neither of above specifies port # */
static len_and_sockaddr* str2sockaddr(
		const char *host, int port,
USE_FEATURE_IPV6(sa_family_t af,)
		int ai_flags)
{
	int rc;
	len_and_sockaddr *r = NULL;
	struct addrinfo *result = NULL;
	struct addrinfo *used_res;
	const char *org_host = host; /* only for error msg */
	const char *cp;
	struct addrinfo hint;

	/* Ugly parsing of host:addr */
	if (ENABLE_FEATURE_IPV6 && host[0] == '[') {
		/* Even uglier parsing of [xx]:nn */
		host++;
		cp = strchr(host, ']');
		if (!cp || cp[1] != ':') { /* Malformed: must have [xx]:nn */
			bb_error_msg("bad address '%s'", org_host);
			if (ai_flags & DIE_ON_ERROR)
				xfunc_die();
			return NULL;
		}
	} else {
		cp = strrchr(host, ':');
		if (ENABLE_FEATURE_IPV6 && cp && strchr(host, ':') != cp) {
			/* There is more than one ':' (e.g. "::1") */
			cp = NULL; /* it's not a port spec */
		}
	}
	if (cp) { /* points to ":" or "]:" */
		int sz = cp - host + 1;
		host = safe_strncpy(alloca(sz), host, sz);
		if (ENABLE_FEATURE_IPV6 && *cp != ':')
			cp++; /* skip ']' */
		cp++; /* skip ':' */
		port = bb_strtou(cp, NULL, 10);
		if (errno || (unsigned)port > 0xffff) {
			bb_error_msg("bad port spec '%s'", org_host);
			if (ai_flags & DIE_ON_ERROR)
				xfunc_die();
			return NULL;
		}
	}

	memset(&hint, 0 , sizeof(hint));
#if !ENABLE_FEATURE_IPV6
	hint.ai_family = AF_INET; /* do not try to find IPv6 */
#else
	hint.ai_family = af;
#endif
	/* Needed. Or else we will get each address thrice (or more)
	 * for each possible socket type (tcp,udp,raw...): */
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = ai_flags & ~DIE_ON_ERROR;
	rc = getaddrinfo(host, NULL, &hint, &result);
	if (rc || !result) {
		bb_error_msg("bad address '%s'", org_host);
		if (ai_flags & DIE_ON_ERROR)
			xfunc_die();
		goto ret;
	}
	used_res = result;
#if ENABLE_FEATURE_PREFER_IPV4_ADDRESS
	while (1) {
		if (used_res->ai_family == AF_INET)
			break;
		used_res = used_res->ai_next;
		if (!used_res) {
			used_res = result;
			break;
		}
	}
#endif
	r = xmalloc(offsetof(len_and_sockaddr, u.sa) + used_res->ai_addrlen);
	r->len = used_res->ai_addrlen;
	memcpy(&r->u.sa, used_res->ai_addr, used_res->ai_addrlen);
	set_nport(r, htons(port));
 ret:
	freeaddrinfo(result);
	return r;
}
#if !ENABLE_FEATURE_IPV6
#define str2sockaddr(host, port, af, ai_flags) str2sockaddr(host, port, ai_flags)
#endif

len_and_sockaddr* FAST_FUNC xhost2sockaddr(const char *host, int port)
{
	return str2sockaddr(host, port, AF_UNSPEC, DIE_ON_ERROR);
}

char* FAST_FUNC xmalloc_sockaddr2dotted(const struct sockaddr *sa)
{
	return sockaddr2str(sa, NI_NUMERICHOST);
}

// Die with an error message if we can't write the entire buffer.
void FAST_FUNC xwrite(int fd, const void *buf, size_t count)
{
	if (count) {
		ssize_t size = full_write(fd, buf, count);
		if ((size_t)size != count)
			bb_error_msg_and_die("short write");
	}
}

// Die with an error message if we can't lseek to the right spot.
off_t FAST_FUNC xlseek(int fd, off_t offset, int whence)
{
	off_t off = lseek(fd, offset, whence);
	if (off == (off_t)-1) {
		if (whence == SEEK_SET)
			bb_perror_msg_and_die("lseek(%"OFF_FMT"u)", offset);
		bb_perror_msg_and_die("lseek");
	}
	return off;
}

/* Return port number for a service.
 * If "port" is a number use it as the port.
 * If "port" is a name it is looked up in /etc/services, if it isnt found return
 * default_port */
unsigned FAST_FUNC bb_lookup_port(const char *port, const char *protocol, unsigned default_port)
{
	unsigned port_nr = default_port;
	if (port) {
		int old_errno;

		/* Since this is a lib function, we're not allowed to reset errno to 0.
		 * Doing so could break an app that is deferring checking of errno. */
		old_errno = errno;
		port_nr = bb_strtou(port, NULL, 10);
		if (errno || port_nr > 65535) {
			struct servent *tserv = getservbyname(port, protocol);
			port_nr = default_port;
			if (tserv)
				port_nr = ntohs(tserv->s_port);
		}
		errno = old_errno;
	}
	return (uint16_t)port_nr;
}

char* FAST_FUNC str_tolower(char *str)
{
	char *c;
	for (c = str; *c; ++c)
		*c = tolower(*c);
	return str;
}


#define ENABLE_GETOPT_LONG 0
const char *const bb_argv_dash[] = { "-", NULL };

const char *opt_complementary;

enum {
	PARAM_STRING,
	PARAM_LIST,
	PARAM_INT,
};

typedef struct {
	unsigned char opt_char;
	smallint param_type;
	unsigned switch_on;
	unsigned switch_off;
	unsigned incongruously;
	unsigned requires;
	void **optarg;  /* char**, llist_t** or int *. */
	int *counter;
} t_complementary;

/* You can set applet_long_options for parse called long options */
#if ENABLE_GETOPT_LONG
static const struct option bb_null_long_options[1] = {
	{ 0, 0, 0, 0 }
};
const char *applet_long_options;
#endif

uint32_t option_mask32;

void bb_show_usage(void)
{
	fputs(wget_full_usage "\n", stdout);
	exit(EXIT_FAILURE);
}

uint32_t FAST_FUNC
getopt32(char **argv, const char *applet_opts, ...)
{
	int argc;
	unsigned flags = 0;
	unsigned requires = 0;
	t_complementary complementary[33]; /* last stays zero-filled */
	int c;
	const unsigned char *s;
	t_complementary *on_off;
	va_list p;
#if ENABLE_GETOPT_LONG
	const struct option *l_o;
	struct option *long_options = (struct option *) &bb_null_long_options;
#endif
	unsigned trigger;
	char **pargv;
	int min_arg = 0;
	int max_arg = -1;

#define SHOW_USAGE_IF_ERROR     1
#define ALL_ARGV_IS_OPTS        2
#define FIRST_ARGV_IS_OPT       4

	int spec_flgs = 0;

	/* skip 0: some applets cheat: they do not actually HAVE argv[0] */
	argc = 1;
	while (argv[argc])
		argc++;

	va_start(p, applet_opts);

	c = 0;
	on_off = complementary;
	memset(on_off, 0, sizeof(complementary));

	/* skip GNU extension */
	s = (const unsigned char *)applet_opts;
	if (*s == '+' || *s == '-')
		s++;
	while (*s) {
		if (c >= 32)
			break;
		on_off->opt_char = *s;
		on_off->switch_on = (1 << c);
		if (*++s == ':') {
			on_off->optarg = va_arg(p, void **);
			while (*++s == ':')
				continue;
		}
		on_off++;
		c++;
	}

#if ENABLE_GETOPT_LONG
	if (applet_long_options) {
		const char *optstr;
		unsigned i, count;

		count = 1;
		optstr = applet_long_options;
		while (optstr[0]) {
			optstr += strlen(optstr) + 3; /* skip NUL, has_arg, val */
			count++;
		}
		/* count == no. of longopts + 1 */
		long_options = alloca(count * sizeof(*long_options));
		memset(long_options, 0, count * sizeof(*long_options));
		i = 0;
		optstr = applet_long_options;
		while (--count) {
			long_options[i].name = optstr;
			optstr += strlen(optstr) + 1;
			long_options[i].has_arg = (unsigned char)(*optstr++);
			/* long_options[i].flag = NULL; */
			long_options[i].val = (unsigned char)(*optstr++);
			i++;
		}
		for (l_o = long_options; l_o->name; l_o++) {
			if (l_o->flag)
				continue;
			for (on_off = complementary; on_off->opt_char; on_off++)
				if (on_off->opt_char == l_o->val)
					goto next_long;
			if (c >= 32)
				break;
			on_off->opt_char = l_o->val;
			on_off->switch_on = (1 << c);
			if (l_o->has_arg != no_argument)
				on_off->optarg = va_arg(p, void **);
			c++;
 next_long: ;
		}
	}
#endif /* ENABLE_GETOPT_LONG */
	for (s = (const unsigned char *)opt_complementary; s && *s; s++) {
		t_complementary *pair;
		unsigned *pair_switch;

		if (*s == ':')
			continue;
		c = s[1];
		if (*s == '?') {
			if (c < '0' || c > '9') {
				spec_flgs |= SHOW_USAGE_IF_ERROR;
			} else {
				max_arg = c - '0';
				s++;
			}
			continue;
		}
		if (*s == '-') {
			if (c < '0' || c > '9') {
				if (c == '-') {
					spec_flgs |= FIRST_ARGV_IS_OPT;
					s++;
				} else
					spec_flgs |= ALL_ARGV_IS_OPTS;
			} else {
				min_arg = c - '0';
				s++;
			}
			continue;
		}
		if (*s == '=') {
			min_arg = max_arg = c - '0';
			s++;
			continue;
		}
		for (on_off = complementary; on_off->opt_char; on_off++)
			if (on_off->opt_char == *s)
				break;
		if (c == ':' && s[2] == ':') {
			on_off->param_type = PARAM_LIST;
			continue;
		}
		if (c == '+' && (s[2] == ':' || s[2] == '\0')) {
			on_off->param_type = PARAM_INT;
			continue;
		}
		if (c == ':' || c == '\0') {
			requires |= on_off->switch_on;
			continue;
		}
		if (c == '-' && (s[2] == ':' || s[2] == '\0')) {
			flags |= on_off->switch_on;
			on_off->incongruously |= on_off->switch_on;
			s++;
			continue;
		}
		if (c == *s) {
			on_off->counter = va_arg(p, int *);
			s++;
		}
		pair = on_off;
		pair_switch = &(pair->switch_on);
		for (s++; *s && *s != ':'; s++) {
			if (*s == '?') {
				pair_switch = &(pair->requires);
			} else if (*s == '-') {
				if (pair_switch == &(pair->switch_off))
					pair_switch = &(pair->incongruously);
				else
					pair_switch = &(pair->switch_off);
			} else {
				for (on_off = complementary; on_off->opt_char; on_off++)
					if (on_off->opt_char == *s) {
						*pair_switch |= on_off->switch_on;
						break;
					}
			}
		}
		s--;
	}
	va_end(p);

	if (spec_flgs & (FIRST_ARGV_IS_OPT | ALL_ARGV_IS_OPTS)) {
		pargv = argv + 1;
		while (*pargv) {
			if (pargv[0][0] != '-' && pargv[0][0] != '\0') {
				/* Can't use alloca: opts with params will
				 * return pointers to stack!
				 * NB: we leak these allocations... */
				char *pp = xmalloc(strlen(*pargv) + 2);
				*pp = '-';
				strcpy(pp + 1, *pargv);
				*pargv = pp;
			}
			if (!(spec_flgs & ALL_ARGV_IS_OPTS))
				break; 
			pargv++;
		}
	}

	/* In case getopt32 was already called:
	 * reset the libc getopt() function, which keeps internal state.
	 *
	 * BSD-derived getopt() functions require that optind be set to 1 in
	 * order to reset getopt() state.  This used to be generally accepted
	 * way of resetting getopt().  However, glibc's getopt()
	 * has additional getopt() state beyond optind, and requires that
	 * optind be set to zero to reset its state.  So the unfortunate state of
	 * affairs is that BSD-derived versions of getopt() misbehave if
	 * optind is set to 0 in order to reset getopt(), and glibc's getopt()
	 * will core dump if optind is set 1 in order to reset getopt().
	 *
	 * More modern versions of BSD require that optreset be set to 1 in
	 * order to reset getopt().   Sigh.  Standards, anyone?
	 */
#ifdef __GLIBC__
	optind = 0;
#else /* BSD style */
	optind = 1;
	/* optreset = 1; */
#endif
	/* optarg = NULL; opterr = 0; optopt = 0; - do we need this?? */
	pargv = NULL;

	/* Note: just "getopt() <= 0" will not work well for
	 * "fake" short options, like this one:
	 * wget $'-\203' "Test: test" http://kernel.org/
	 * (supposed to act as --header, but doesn't) */
#if ENABLE_GETOPT_LONG
	while ((c = getopt_long(argc, argv, applet_opts,
			long_options, NULL)) != -1) {
#else
	while ((c = getopt(argc, argv, applet_opts)) != -1) {
#endif
		/* getopt prints "option requires an argument -- X"
		 * and returns '?' if an option has no arg, but one is reqd */
		c &= 0xff; /* fight libc's sign extension */
		for (on_off = complementary; on_off->opt_char != c; on_off++) {
			/* c can be NUL if long opt has non-NULL ->flag,
			 * but we construct long opts so that flag
			 * is always NULL (see above) */
			if (on_off->opt_char == '\0' /* && c != '\0' */) {
				/* c is probably '?' - "bad option" */
				bb_show_usage();
			}
		}
		if (flags & on_off->incongruously)
			bb_show_usage();
		trigger = on_off->switch_on & on_off->switch_off;
		flags &= ~(on_off->switch_off ^ trigger);
		flags |= on_off->switch_on ^ trigger;
		flags ^= trigger;
		if (on_off->counter)
			(*(on_off->counter))++;
		if (on_off->param_type == PARAM_LIST) {
			if (optarg)
				llist_add_to_end((llist_t **)(on_off->optarg), optarg);
		} else if (on_off->param_type == PARAM_INT) {
			if (optarg)
//TODO: xatoi_u indirectly pulls in printf machinery
				*(unsigned*)(on_off->optarg) = xatoi_u(optarg);
		} else if (on_off->optarg) {
			if (optarg)
				*(char **)(on_off->optarg) = optarg;
		}
		if (pargv != NULL)
			break;
	}

	/* check depending requires for given options */
	for (on_off = complementary; on_off->opt_char; on_off++) {
		if (on_off->requires && (flags & on_off->switch_on) &&
					(flags & on_off->requires) == 0)
			bb_show_usage();
	}
	if (requires && (flags & requires) == 0)
		bb_show_usage();
	argc -= optind;
	if (argc < min_arg || (max_arg >= 0 && argc > max_arg))
		bb_show_usage();

	option_mask32 = flags;
	return flags;
}


/* It is perfectly ok to pass in a NULL for either width or for
 * height, in which case that value will not be set.  */
int FAST_FUNC get_terminal_width_height(int fd, unsigned *width, unsigned *height)
{
	struct winsize win = { 0, 0, 0, 0 };
	int ret = ioctl(fd, TIOCGWINSZ, &win);

	if (height) {
		if (!win.ws_row) {
			char *s = getenv("LINES");
			if (s) win.ws_row = atoi(s);
		}
		if (win.ws_row <= 1 || win.ws_row >= 30000)
			win.ws_row = 24;
		*height = (int) win.ws_row;
	}

	if (width) {
		if (!win.ws_col) {
			char *s = getenv("COLUMNS");
			if (s) win.ws_col = atoi(s);
		}
		if (win.ws_col <= 1 || win.ws_col >= 30000)
			win.ws_col = 80;
		*width = (int) win.ws_col;
	}

	return ret;
}

#if ENABLE_FEATURE_WGET_STATUSBAR
enum {
	STALLTIME = 5                   /* Seconds when xfer considered "stalled" */
};


static unsigned int getttywidth(void)
{
	unsigned width;
	get_terminal_width_height(0, &width, NULL);
	return width;
}

static void progressmeter(int flag)
{
	/* We can be called from signal handler */
	int save_errno = errno;
	off_t abbrevsize;
	unsigned since_last_update, elapsed;
	unsigned ratio;
	int barlength, i;

	if (flag == -1) { /* first call to progressmeter */
		start_sec = monotonic_sec();
		lastupdate_sec = start_sec;
		lastsize = 0;
		totalsize = content_len + beg_range; /* as content_len changes.. */
	}

	ratio = 100;
	if (totalsize != 0 && !chunked) {
		/* long long helps to have it working even if !LFS */
		ratio = (unsigned) (100ULL * (transferred+beg_range) / totalsize);
		if (ratio > 100) ratio = 100;
	}

	fprintf(stderr, "\r%-20.20s%4d%% ", curfile, ratio);

	barlength = getttywidth() - 49;
	if (barlength > 0) {
		/* god bless gcc for variable arrays :) */
		i = barlength * ratio / 100;
		{
			char buf[i+1];
			memset(buf, '*', i);
			buf[i] = '\0';
			fprintf(stderr, "|%s%*s|", buf, barlength - i, "");
		}
	}
	i = 0;
	abbrevsize = transferred + beg_range;
	while (abbrevsize >= 100000) {
		i++;
		abbrevsize >>= 10;
	}
	/* see http://en.wikipedia.org/wiki/Tera */
	fprintf(stderr, "%6d%c ", (int)abbrevsize, " kMGTPEZY"[i]);

// Nuts! Ain't it easier to update progress meter ONLY when we transferred++?

	elapsed = monotonic_sec();
	since_last_update = elapsed - lastupdate_sec;
	if (transferred > lastsize) {
		lastupdate_sec = elapsed;
		lastsize = transferred;
		if (since_last_update >= STALLTIME) {
			/* We "cut off" these seconds from elapsed time
			 * by adjusting start time */
			start_sec += since_last_update;
		}
		since_last_update = 0; /* we are un-stalled now */
	}
	elapsed -= start_sec; /* now it's "elapsed since start" */

	if (since_last_update >= STALLTIME) {
		fprintf(stderr, " - stalled -");
	} else {
		off_t to_download = totalsize - beg_range;
		if (transferred <= 0 || (int)elapsed <= 0 || transferred > to_download || chunked) {
			fprintf(stderr, "--:--:-- ETA");
		} else {
			/* to_download / (transferred/elapsed) - elapsed: */
			int eta = (int) ((unsigned long long)to_download*elapsed/transferred - elapsed);
			/* (long long helps to have working ETA even if !LFS) */
			i = eta % 3600;
			fprintf(stderr, "%02d:%02d:%02d ETA", eta / 3600, i / 60, i % 60);
		}
	}

	if (flag == 0) {
		/* last call to progressmeter */
		alarm(0);
		transferred = 0;
		fputc('\n', stderr);
	} else {
		if (flag == -1) { /* first call to progressmeter */
			signal_SA_RESTART_empty_mask(SIGALRM, progressmeter);
		}
		alarm(1);
	}

	errno = save_errno;
}
/* Original copyright notice which applies to the CONFIG_FEATURE_WGET_STATUSBAR stuff,
 * much of which was blatantly stolen from openssh.  */
/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. <BSD Advertising Clause omitted per the July 22, 1999 licensing change
 *		ftp://ftp.cs.berkeley.edu/pub/4bsd/README.Impt.License.Change>
 *
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#else /* FEATURE_WGET_STATUSBAR */

static ALWAYS_INLINE void progressmeter(int flag UNUSED_PARAM) { }

#endif


/* Read NMEMB bytes into PTR from STREAM.  Returns the number of bytes read,
 * and a short count if an eof or non-interrupt error is encountered.  */
static size_t safe_fread(void *ptr, size_t nmemb, FILE *stream)
{
	size_t ret;
	char *p = (char*)ptr;

	do {
		clearerr(stream);
		ret = fread(p, 1, nmemb, stream);
		p += ret;
		nmemb -= ret;
	} while (nmemb && ferror(stream) && errno == EINTR);

	return p - (char*)ptr;
}

/* Read a line or SIZE-1 bytes into S, whichever is less, from STREAM.
 * Returns S, or NULL if an eof or non-interrupt error is encountered.  */
static char *safe_fgets(char *s, int size, FILE *stream)
{
	char *ret;

	do {
		clearerr(stream);
		ret = fgets(s, size, stream);
	} while (ret == NULL && ferror(stream) && errno == EINTR);

	return ret;
}

#if ENABLE_FEATURE_WGET_AUTHENTICATION
/* Base64-encode character string. buf is assumed to be char buf[512]. */
static char *base64enc_512(char buf[512], const char *str)
{
	unsigned len = strlen(str);
	if (len > 512/4*3 - 10) /* paranoia */
		len = 512/4*3 - 10;
	bb_uuencode(buf, str, len, bb_uuenc_tbl_base64);
	return buf;
}
#endif


static FILE *open_socket(len_and_sockaddr *lsa)
{
	FILE *fp;

	/* glibc 2.4 seems to try seeking on it - ??! */
	/* hopefully it understands what ESPIPE means... */
	fp = fdopen(xconnect_stream(lsa), "r+");
	if (fp == NULL){
		bb_perror_msg_and_die("fdopen");
	}

	return fp;
}


static int ftpcmd(const char *s1, const char *s2, FILE *fp, char *buf)
{
	int result;
	if (s1) {
		if (!s2) s2 = "";
		fprintf(fp, "%s%s\r\n", s1, s2);
		fflush(fp);
	}

	do {
		char *buf_ptr;

		if (fgets(buf, 510, fp) == NULL) {
			bb_perror_msg_and_die("error getting response");
		}
		buf_ptr = strstr(buf, "\r\n");
		if (buf_ptr) {
			*buf_ptr = '\0';
		}
	} while (!isdigit(buf[0]) || buf[3] != ' ');

	buf[3] = '\0';
	result = xatoi_u(buf);
	buf[3] = ' ';
	return result;
}


static void parse_url(char *src_url, struct host_info *h)
{
	char *url, *p, *sp;

	/* h->allocated = */ url = xstrdup(src_url);

	if (strncmp(url, "http://", 7) == 0) {
		h->port = bb_lookup_port("http", "tcp", 80);
		h->host = url + 7;
		h->is_ftp = 0;
	} else if (strncmp(url, "ftp://", 6) == 0) {
		h->port = bb_lookup_port("ftp", "tcp", 21);
		h->host = url + 6;
		h->is_ftp = 1;
	} else
		bb_error_msg_and_die("not an http or ftp url: %s", url);

	// FYI:
	// "Real" wget 'http://busybox.net?var=a/b' sends this request:
	//   'GET /?var=a/b HTTP 1.0'
	//   and saves 'index.html?var=a%2Fb' (we save 'b')
	// wget 'http://busybox.net?login=john@doe':
	//   request: 'GET /?login=john@doe HTTP/1.0'
	//   saves: 'index.html?login=john@doe' (we save '?login=john@doe')
	// wget 'http://busybox.net#test/test':
	//   request: 'GET / HTTP/1.0'
	//   saves: 'index.html' (we save 'test')
	//
	// We also don't add unique .N suffix if file exists...
	sp = strchr(h->host, '/');
	p = strchr(h->host, '?'); if (!sp || (p && sp > p)) sp = p;
	p = strchr(h->host, '#'); if (!sp || (p && sp > p)) sp = p;
	if (!sp) {
		h->path = "";
	} else if (*sp == '/') {
		*sp = '\0';
		h->path = sp + 1;
	} else { // '#' or '?'
		// http://busybox.net?login=john@doe is a valid URL
		// memmove converts to:
		// http:/busybox.nett?login=john@doe...
		memmove(h->host - 1, h->host, sp - h->host);
		h->host--;
		sp[-1] = '\0';
		h->path = sp;
	}

	sp = strrchr(h->host, '@');
	h->user = NULL;
	if (sp != NULL) {
		h->user = h->host;
		*sp = '\0';
		h->host = sp + 1;
	}

	sp = h->host;
}


static char *gethdr(char *buf, size_t bufsiz, FILE *fp /*, int *istrunc*/)
{
	char *s, *hdrval;
	int c;

	/* *istrunc = 0; */

	/* retrieve header line */
	if (fgets(buf, bufsiz, fp) == NULL)
		return NULL;

	/* see if we are at the end of the headers */
	for (s = buf; *s == '\r'; ++s)
		continue;
	if (*s == '\n')
		return NULL;

	/* convert the header name to lower case */
	for (s = buf; isalnum(*s) || *s == '-' || *s == '.'; ++s)
		*s = tolower(*s);

	/* verify we are at the end of the header name */
	if (*s != ':')
		bb_error_msg_and_die("bad header line: %s", buf);

	/* locate the start of the header value */
	*s++ = '\0';
	hdrval = skip_whitespace(s);

	/* locate the end of header */
	while (*s && *s != '\r' && *s != '\n')
		++s;

	/* end of header found */
	if (*s) {
		*s = '\0';
		return hdrval;
	}

	/* Rats! The buffer isn't big enough to hold the entire header value. */
	while (c = getc(fp), c != EOF && c != '\n')
		continue;
	/* *istrunc = 1; */
	return hdrval;
}


int main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int main(int argc UNUSED_PARAM, char **argv)
{
	char buf[512];
	struct host_info server, target;
	len_and_sockaddr *lsa;
	int status;
	int port;
	int try = 5;
	unsigned opt;
	char *str;
	char *proxy = 0;
	char *dir_prefix = NULL;
#if ENABLE_FEATURE_WGET_LONG_OPTIONS
	char *extra_headers = NULL;
	llist_t *headers_llist = NULL;
#endif
	FILE *sfp = NULL;               /* socket to web/ftp server         */
	FILE *dfp;                      /* socket to ftp server (data)      */
	char *fname_out;                /* where to direct output (-O)      */
	bool got_clen = 0;              /* got content-length: from server  */
	int output_fd = -1;
	bool use_proxy = 1;             /* Use proxies if env vars are set  */
	const char *proxy_flag = "on";  /* Use proxies if env vars are set  */
	const char *user_agent = "Wget";/* "User-Agent" header field        */

	static const char keywords[] ALIGN1 =
		"content-length\0""transfer-encoding\0""chunked\0""location\0";
	enum {
		KEY_content_length = 1, KEY_transfer_encoding, KEY_chunked, KEY_location
	};
	enum {
		WGET_OPT_CONTINUE   = 0x1,
		WGET_OPT_SPIDER	    = 0x2,
		WGET_OPT_QUIET      = 0x4,
		WGET_OPT_OUTNAME    = 0x8,
		WGET_OPT_PREFIX     = 0x10,
		WGET_OPT_PROXY      = 0x20,
		WGET_OPT_USER_AGENT = 0x40,
		WGET_OPT_PASSIVE    = 0x80,
		WGET_OPT_HEADER     = 0x100,
	};
#if ENABLE_FEATURE_WGET_LONG_OPTIONS
	static const char wget_longopts[] ALIGN1 =
		/* name, has_arg, val */
		"continue\0"         No_argument       "c"
		"spider\0"           No_argument       "s"
		"quiet\0"            No_argument       "q"
		"output-document\0"  Required_argument "O"
		"directory-prefix\0" Required_argument "P"
		"proxy\0"            Required_argument "Y"
		"user-agent\0"       Required_argument "U"
		"passive-ftp\0"      No_argument       "\xff"
		"header\0"           Required_argument "\xfe"
		;
#endif

	INIT_G();

#if ENABLE_FEATURE_WGET_LONG_OPTIONS
	applet_long_options = wget_longopts;
#endif
	/* server.allocated = target.allocated = NULL; */
	opt_complementary = "-1" USE_FEATURE_WGET_LONG_OPTIONS(":\xfe::");
	opt = getopt32(argv, "csqO:P:Y:U:" /*ignored:*/ "t:T:",
				&fname_out, &dir_prefix,
				&proxy_flag, &user_agent,
				NULL, /* -t RETRIES */
				NULL /* -T NETWORK_READ_TIMEOUT */
				USE_FEATURE_WGET_LONG_OPTIONS(, &headers_llist)
				);
	if (strcmp(proxy_flag, "off") == 0) {
		/* Use the proxy if necessary */
		use_proxy = 0;
	}
#if ENABLE_FEATURE_WGET_LONG_OPTIONS
	if (headers_llist) {
		int size = 1;
		char *cp;
		llist_t *ll = headers_llist;
		while (ll) {
			size += strlen(ll->data) + 2;
			ll = ll->link;
		}
		extra_headers = cp = xmalloc(size);
		while (headers_llist) {
			cp += sprintf(cp, "%s\r\n", (char*)llist_pop(&headers_llist));
		}
	}
#endif

	parse_url(argv[optind], &target);
	server.host = target.host;
	server.port = target.port;

	/* Use the proxy if necessary */
	if (use_proxy) {
		proxy = getenv(target.is_ftp ? "ftp_proxy" : "http_proxy");
		if (proxy && *proxy) {
			parse_url(proxy, &server);
		} else {
			use_proxy = 0;
		}
	}

	/* Guess an output filename, if there was no -O FILE */
	if (!(opt & WGET_OPT_OUTNAME)) {
		fname_out = bb_get_last_path_component_nostrip(target.path);
		/* handle "wget http://kernel.org//" */
		if (fname_out[0] == '/' || !fname_out[0])
			fname_out = (char*)"index.html";
		/* -P DIR is considered only if there was no -O FILE */
		if (dir_prefix)
			fname_out = concat_path_file(dir_prefix, fname_out);
	} else {
		if (LONE_DASH(fname_out)) {
			/* -O - */
			output_fd = 1;
			opt &= ~WGET_OPT_CONTINUE;
		}
	}
#if ENABLE_FEATURE_WGET_STATUSBAR
	curfile = bb_get_last_path_component_nostrip(fname_out);
#endif

	/* Impossible?
	if ((opt & WGET_OPT_CONTINUE) && !fname_out)
		bb_error_msg_and_die("cannot specify continue (-c) without a filename (-O)"); */

	/* Determine where to start transfer */
	if (opt & WGET_OPT_CONTINUE) {
		output_fd = open(fname_out, O_WRONLY);
		if (output_fd >= 0) {
			beg_range = xlseek(output_fd, 0, SEEK_END);
		}
		/* File doesn't exist. We do not create file here yet.
		   We are not sure it exists on remove side */
	}

	/* We want to do exactly _one_ DNS lookup, since some
	 * sites (i.e. ftp.us.debian.org) use round-robin DNS
	 * and we want to connect to only one IP... */
	lsa = xhost2sockaddr(server.host, server.port);
	if (!(opt & WGET_OPT_QUIET)) {
		fprintf(stderr, "Connecting to %s (%s)\n", server.host,
				xmalloc_sockaddr2dotted(&lsa->u.sa));
		/* We leak result of xmalloc_sockaddr2dotted */
	}

	if (use_proxy || !target.is_ftp) {
		/*
		 *  HTTP session
		 */
		do {
			got_clen = 0;
			chunked = 0;

			if (!--try)
				bb_error_msg_and_die("too many redirections");
			/* Open socket to http server */
			if (sfp) fclose(sfp);
			sfp = open_socket(lsa);

			/* Send HTTP request.  */
			if (use_proxy) {
				fprintf(sfp, "GET %stp://%s/%s HTTP/1.1\r\n",
					target.is_ftp ? "f" : "ht", target.host,
					target.path);
			} else {
				fprintf(sfp, "GET /%s HTTP/1.1\r\n", target.path);
			}

			fprintf(sfp, "Host: %s\r\nUser-Agent: %s\r\n",
				target.host, user_agent);

#if ENABLE_FEATURE_WGET_AUTHENTICATION
			if (target.user) {
				fprintf(sfp, "Proxy-Authorization: Basic %s\r\n"+6,
					base64enc_512(buf, target.user));
			}
			if (use_proxy && server.user) {
				fprintf(sfp, "Proxy-Authorization: Basic %s\r\n",
					base64enc_512(buf, server.user));
			}
#endif

			if (beg_range)
				fprintf(sfp, "Range: bytes=%"OFF_FMT"d-\r\n", beg_range);
#if ENABLE_FEATURE_WGET_LONG_OPTIONS
			if (extra_headers)
				fputs(extra_headers, sfp);
#endif
			fprintf(sfp, "Connection: close\r\n\r\n");

			/*
			* Retrieve HTTP response line and check for "200" status code.
			*/
 read_response:
			if (fgets(buf, sizeof(buf), sfp) == NULL)
				bb_error_msg_and_die("no response from server");

			str = buf;
			str = skip_non_whitespace(str);
			str = skip_whitespace(str);
			// FIXME: no error check
			// xatou wouldn't work: "200 OK"
			status = atoi(str);
			switch (status) {
			case 0:
			case 100:
				while (gethdr(buf, sizeof(buf), sfp /*, &n*/) != NULL)
					/* eat all remaining headers */;
				goto read_response;
			case 200:
/*
Response 204 doesn't say "null file", it says "metadata
has changed but data didn't":

"10.2.5 204 No Content
The server has fulfilled the request but does not need to return
an entity-body, and might want to return updated metainformation.
The response MAY include new or updated metainformation in the form
of entity-headers, which if present SHOULD be associated with
the requested variant.

If the client is a user agent, it SHOULD NOT change its document
view from that which caused the request to be sent. This response
is primarily intended to allow input for actions to take place
without causing a change to the user agent's active document view,
although any new or updated metainformation SHOULD be applied
to the document currently in the user agent's active view.

The 204 response MUST NOT include a message-body, and thus
is always terminated by the first empty line after the header fields."

However, in real world it was observed that some web servers
(e.g. Boa/0.94.14rc21) simply use code 204 when file size is zero.
*/
			case 204:
				break;
			case 300:	/* redirection */
			case 301:
			case 302:
			case 303:
				break;
			case 206:
				if (beg_range)
					break;
				/* fall through */
			default:
				/* Show first line only and kill any ESC tricks */
				buf[strcspn(buf, "\n\r\x1b")] = '\0';
				bb_error_msg_and_die("server returned error: %s", buf);
			}

			/*
			 * Retrieve HTTP headers.
			 */
			while ((str = gethdr(buf, sizeof(buf), sfp /*, &n*/)) != NULL) {
				/* gethdr did already convert the "FOO:" string to lowercase */
				smalluint key = index_in_strings(keywords, *&buf) + 1;
				if (key == KEY_content_length) {
					content_len = BB_STRTOOFF(str, NULL, 10);
					if (errno || content_len < 0) {
						bb_error_msg_and_die("content-length %s is garbage", str);
					}
					got_clen = 1;
					continue;
				}
				if (key == KEY_transfer_encoding) {
					if (index_in_strings(keywords, str_tolower(str)) + 1 != KEY_chunked)
						bb_error_msg_and_die("transfer encoding '%s' is not supported", str);
					chunked = got_clen = 1;
				}
				if (key == KEY_location) {
					if (str[0] == '/')
						/* free(target.allocated); */
						target.path = /* target.allocated = */ xstrdup(str+1);
					else {
						parse_url(str, &target);
						if (use_proxy == 0) {
							server.host = target.host;
							server.port = target.port;
						}
						free(lsa);
						lsa = xhost2sockaddr(server.host, server.port);
						break;
					}
				}
			}
		} while (status >= 300);

		dfp = sfp;

	} else {

		/*
		 *  FTP session
		 */
		if (!target.user)
			target.user = xstrdup("anonymous:busybox@");

		sfp = open_socket(lsa);
		if (ftpcmd(NULL, NULL, sfp, buf) != 220)
			bb_error_msg_and_die("%s", buf+4);

		/*
		 * Splitting username:password pair,
		 * trying to log in
		 */
		str = strchr(target.user, ':');
		if (str)
			*(str++) = '\0';
		switch (ftpcmd("USER ", target.user, sfp, buf)) {
		case 230:
			break;
		case 331:
			if (ftpcmd("PASS ", str, sfp, buf) == 230)
				break;
			/* fall through (failed login) */
		default:
			bb_error_msg_and_die("ftp login: %s", buf+4);
		}

		ftpcmd("TYPE I", NULL, sfp, buf);

		/*
		 * Querying file size
		 */
		if (ftpcmd("SIZE ", target.path, sfp, buf) == 213) {
			content_len = BB_STRTOOFF(buf+4, NULL, 10);
			if (errno || content_len < 0) {
				bb_error_msg_and_die("SIZE value is garbage");
			}
			got_clen = 1;
		}

		/*
		 * Entering passive mode
		 */
		if (ftpcmd("PASV", NULL, sfp, buf) != 227) {
 pasv_error:
			bb_error_msg_and_die("bad response to %s: %s", "PASV", buf);
		}
		// Response is "227 garbageN1,N2,N3,N4,P1,P2[)garbage]
		// Server's IP is N1.N2.N3.N4 (we ignore it)
		// Server's port for data connection is P1*256+P2
		str = strrchr(buf, ')');
		if (str) str[0] = '\0';
		str = strrchr(buf, ',');
		if (!str) goto pasv_error;
		port = xatou_range(str+1, 0, 255);
		*str = '\0';
		str = strrchr(buf, ',');
		if (!str) goto pasv_error;
		port += xatou_range(str+1, 0, 255) * 256;
		set_nport(lsa, htons(port));
		dfp = open_socket(lsa);

		if (beg_range) {
			sprintf(buf, "REST %"OFF_FMT"d", beg_range);
			if (ftpcmd(buf, NULL, sfp, buf) == 350)
				content_len -= beg_range;
		}

		if (ftpcmd("RETR ", target.path, sfp, buf) > 150)
			bb_error_msg_and_die("bad response to %s: %s", "RETR", buf);
	}

	if (opt & WGET_OPT_SPIDER) {
		if (ENABLE_FEATURE_CLEAN_UP)
			fclose(sfp);
		return EXIT_SUCCESS;
	}

	/*
	 * Retrieve file
	 */

	/* Do it before progressmeter (want to have nice error message) */
	if (output_fd < 0) {
		int o_flags = O_WRONLY | O_CREAT | O_TRUNC | O_EXCL;
		/* compat with wget: -O FILE can overwrite */
		if (opt & WGET_OPT_OUTNAME)
			o_flags = O_WRONLY | O_CREAT | O_TRUNC;
		output_fd = xopen(fname_out, o_flags);
	}

	if (!(opt & WGET_OPT_QUIET))
		progressmeter(-1);

	if (chunked)
		goto get_clen;

	/* Loops only if chunked */
	while (1) {
		while (content_len > 0 || !got_clen) {
			int n;
			unsigned rdsz = sizeof(buf);

			if (content_len < sizeof(buf) && (chunked || got_clen))
				rdsz = (unsigned)content_len;
			n = safe_fread(buf, rdsz, dfp);
			if (n <= 0) {
				if (ferror(dfp)) {
					/* perror will not work: ferror doesn't set errno */
					bb_error_msg_and_die(bb_msg_read_error);
				}
				break;
			}
			xwrite(output_fd, buf, n);
#if ENABLE_FEATURE_WGET_STATUSBAR
			transferred += n;
#endif
			if (got_clen)
				content_len -= n;
		}

		if (!chunked)
			break;

		safe_fgets(buf, sizeof(buf), dfp); /* This is a newline */
 get_clen:
		safe_fgets(buf, sizeof(buf), dfp);
		content_len = STRTOOFF(buf, NULL, 16);
		/* FIXME: error check? */
		if (content_len == 0)
			break; /* all done! */
	}

	if (!(opt & WGET_OPT_QUIET))
		progressmeter(0);

	if ((use_proxy == 0) && target.is_ftp) {
		fclose(dfp);
		if (ftpcmd(NULL, NULL, sfp, buf) != 226)
			bb_error_msg_and_die("ftp error: %s", buf+4);
		ftpcmd("QUIT", NULL, sfp, buf);
	}

	return EXIT_SUCCESS;
}
