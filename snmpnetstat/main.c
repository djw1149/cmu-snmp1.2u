#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/snmpnetstat/main.c,v 1.4 1992/08/28 13:59:06 djw Exp $";
#endif

/***********************************************************
	Copyright 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
/*
 * Copyright (c) 1983,1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of California at Berkeley. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1983 Regents of the University of California.\n\
 All rights reserved.\n";
#endif not lint

#include <sys/types.h>
#include <sys/param.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <netinet/in.h>
#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"

/* internet protocols */
extern	int protopr();
extern	int tcp_stats(), udp_stats(), ip_stats(), icmp_stats();

#define NULLPROTOX	((struct protox *) 0)
struct protox {
	u_char	pr_wanted;		/* 1 if wanted, 0 otherwise */
	int	(*pr_cblocks)();	/* control blocks printing routine */
	int	(*pr_stats)();		/* statistics printing routine */
	char	*pr_name;		/* well-known name */
} protox[] = {
	{ 1,	protopr,    tcp_stats,	"tcp" },
	{ 1,	0,	    udp_stats,	"udp" },
	{ 1,	0,	    ip_stats,	"ip" },
	{ 1,	0,	    icmp_stats,	"icmp" },
	{ 0,	0,	    0,		0 }
};

int	aflag;
int	iflag;
int	nflag;
int	pflag;
int	rflag;
int	sflag;
int	interval;
char	*interface;
char	usage[] = "host community [ -ainrs ] [-p proto] [-I interface] [ interval ]";

int debug = 0;


extern	char *malloc();

struct snmp_session *Session;
int snmp_dump_packet = 0;
int print_errors = 0;

main(argc, argv)
	int argc;
	char *argv[];
{
	char *cp, *name;
	char *host;
	register struct protoent *p;
	register struct protox *tp;	/* for printing cblocks & stats */
	struct protox *name2protox();	/* for -p */
	char *community;
	struct snmp_session session;
	
	name = argv[0];
	argc--, argv++;
	if (argc--)
	    host = *argv++;
	else
	    goto use;
	if (argc--)
	    community = *argv++;
	else
	    goto use;
  	while (argc > 0 && **argv == '-') {
		for (cp = &argv[0][1]; *cp; cp++)
		switch(*cp) {

		case 'a':
			aflag++;
			break;

		case 'i':
			iflag++;
			break;

		case 'n':
			nflag++;
			break;

		case 'r':
			rflag++;
			break;

		case 's':
			sflag++;
			break;

		case 'p':
			argv++;
			argc--;
			if (argc == 0)
				goto use;
			if ((tp = name2protox(*argv)) == NULLPROTOX) {
				fprintf(stderr, "%s: unknown or uninstrumented protocol\n",
					*argv);
				exit(10);
			}
			pflag++;
			break;

		case 'I':
			iflag++;
			if (*(interface = cp + 1) == 0) {
				if ((interface = argv[1]) == 0)
					break;
				argv++;
				argc--;
			}
			for (cp = interface; *cp; cp++)
				;
			cp--;
			break;

		default:
use:
			printf("usage: %s %s\n", name, usage);
			exit(1);
		}
		argv++, argc--;
	}
	if (argc > 0 && isdigit(argv[0][0])) {
		interval = atoi(argv[0]);
		if (interval <= 0)
			goto use;
		argv++, argc--;
		iflag++;
	}

	bzero((char *)&session, sizeof(struct snmp_session));
	session.peername = host;
	session.community = (u_char *)community;
	session.community_len = strlen((char *)community);
	session.retries = SNMP_DEFAULT_RETRIES;
	session.timeout = SNMP_DEFAULT_TIMEOUT;
	session.authenticator = NULL;
	snmp_synch_setup(&session);
	Session = snmp_open(&session);
	if (Session == NULL){
	    printf("Couldn't open snmp session\n");
	    exit(-1);
	}
	if (pflag) {
		if (tp->pr_stats)
		{
		    (*tp->pr_stats)();
		    exit(0);
		}
		else
		{
		    printf("%s: no stats routine\n", tp->pr_name);
		    exit(-1);
		}
	}
	/*
	 * Keep file descriptors open to avoid overhead
	 * of open/close on each call to get* routines.
	 */
	sethostent(1);
	setnetent(1);
	if (iflag) {
	    if (intpr(interval))
		exit(-1);
	    else
		exit(0);
	}
	if (rflag) {
	    if (sflag)
		if (rt_stats())
		    exit(-1);
		else
		    exit(0);
	    else
		if (routepr())
		    exit(-1);
		else
		    exit(0);
	}

	setprotoent(1);
	setservent(1);
	while (p = getprotoent()) {

		for (tp = protox; tp->pr_name; tp++)
			if (strcmp(tp->pr_name, p->p_name) == 0)
				break;
		if (tp->pr_name == 0 || tp->pr_wanted == 0)
			continue;
		if (sflag) {
			if (tp->pr_stats)
				(*tp->pr_stats)();
		} else
			if (tp->pr_cblocks)
				(*tp->pr_cblocks)();
	}
	endprotoent();
	exit(0);
}

char *
plural(n)
	int n;
{

	return (n != 1 ? "s" : "");
}

/*
 * Find the protox for the given "well-known" name.
 */
struct protox *
knownname(name)
	char *name;
{
	struct protox *tp;
	
	for (tp = protox; tp->pr_name; tp++)
		if (strcmp(tp->pr_name, name) == 0)
			return(tp);
	return(NULLPROTOX);
}

/*
 * Find the protox corresponding to name.
 */
struct protox *
name2protox(name)
	char *name;
{
	struct protox *tp;
	char **alias;			/* alias from p->aliases */
	struct protoent *p;
	
	/*
	 * Try to find the name in the list of "well-known" names. If that
	 * fails, check if name is an alias for an Internet protocol.
	 */
	if (tp = knownname(name))
		return(tp);
		
	setprotoent(1);			/* make protocol lookup cheaper */
	while (p = getprotoent()) {
		/* assert: name not same as p->name */
		for (alias = p->p_aliases; *alias; alias++)
			if (strcmp(name, *alias) == 0) {
				endprotoent();
				return(knownname(p->p_name));
			}
	}
	endprotoent();
	return(NULLPROTOX);
}
