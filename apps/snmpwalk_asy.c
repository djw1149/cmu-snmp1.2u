#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmpwalk_asy.c,v 1.2 1992/07/29 18:17:24 djw Exp $";
#endif

/*
 * snmpwalk.c - send snmp GETNEXT requests to a network entity, walking a subtree.
 * This uses the asynchronous interface directly.
 *
 */
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <errno.h>

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"

#ifndef BSD4_3
#define BSD4_2
#endif

#ifndef BSD4_3

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid objid_mib[] = {1, 3, 6, 1, 2, 1};

extern int  errno;
int	snmp_dump_packet = 0;
struct state {
    oid	name[MAX_NAME_LEN];
    int name_length;
    oid root[MAX_NAME_LEN];
    int	rootlen;
    int running;
    int waiting;
} state_info;

/*ARGUSED*/
snmp_input(op,  session, reqid, pdu, magic)
    int op;
    struct snmp_session *session;	/* unused */
    int reqid;				/* unused */
    struct snmp_pdu *pdu;
    void *magic;
{
    struct variable_list *vars;
    struct state *state = (struct state *)magic;
    int count;

    state->waiting = 0;
    state->running = 0;
    if (op == RECEIVED_MESSAGE && pdu->command == GET_RSP_MSG){
	if (pdu->errstat == SNMP_ERR_NOERROR){
	    for(vars = pdu->variables; vars; vars = vars->next_variable){
		if (vars->name_length < state->rootlen || bcmp(state->root, vars->name, state->rootlen * sizeof(oid)))
		    continue;	/* not part of this subtree */
		print_variable(vars->name, vars->name_length, vars);
		bcopy((char *)vars->name, (char *)state->name, vars->name_length * sizeof(oid));
		state->name_length = vars->name_length;
		state->running = 1; /* restart so we can get next variable */
	    }
	} else {
	    if (pdu->errstat == SNMP_ERR_NOSUCHNAME){
		printf("End of MIB.\n");
	    } else {
		printf("Error in packet.\nReason: %s\n", snmp_errstring(pdu->errstat));
		if (pdu->errstat == SNMP_ERR_NOSUCHNAME){
		    printf("The request for this object identifier failed: ");
		    for(count = 1, vars = pdu->variables; vars && count != pdu->errindex;
			vars = vars->next_variable, count++)
			    ;
		    if (vars)
			print_objid(vars->name, vars->name_length);
		    printf("\n");
		}
	    }
	}
    } else if (op == TIMED_OUT){
	/* We don't restart on timeout so main will exit */
	printf("Timed Out\n");
    }
    return 1;
}

main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session	session, *ss;
    struct snmp_pdu *pdu;
    int	arg;
    char *gateway = NULL;
    char *community = NULL;
    int	count, numfds, gotroot = 0, block;
    fd_set fdset;
    struct timeval timeout, *tvp;
    struct state *state = &state_info;

    init_mib();
    /*
     * usage: snmpwalk gateway-name community-name [object-id]
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
		case 'd':
		    snmp_dump_packet++;
		    break;
		default:
		    printf("invalid option: -%c\n", argv[arg][1]);
		    break;
	    }
	    continue;
	}
	if (gateway == NULL){
	    gateway = argv[arg];
	} else if (community == NULL){
	    community = argv[arg]; 
	} else {
	    state->rootlen = MAX_NAME_LEN;
	    if (read_objid(argv[arg], state->root, &state->rootlen)){
		gotroot = 1;
	    } else {
		printf("Invalid object identifier: %s\n", argv[arg]);
	    }
	}
    }

    if (gotroot == 0){
	bcopy((char *)objid_mib, (char *)state->root, sizeof(objid_mib));
	state->rootlen = sizeof(objid_mib) / sizeof(oid);
	gotroot = 1;
    }

    if (!(gateway && community && gotroot == 1)){
	printf("usage: snmpwalk gateway-name community-name object-identifier\n");
	exit(1);
    }

    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = gateway;
    session.community = (u_char *)community;
    session.community_len = strlen((char *)community);
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.authenticator = NULL;
    session.callback = snmp_input;
    session.callback_magic = (void *)state;
    ss = snmp_open(&session);
    if (ss == NULL){
	printf("Couldn't open snmp\n");
	exit(-1);
    }

    state->running = 1;
    state->waiting = 0;
    bcopy((char *)state->root, (char *)state->name, state->rootlen * sizeof(oid));
    state->name_length = state->rootlen;

    while(state->running){
	if (!state->waiting){
	    pdu = snmp_pdu_create(GETNEXT_REQ_MSG);

	    snmp_add_null_var(pdu, state->name, state->name_length);

	    if (snmp_send(ss, pdu) == 0){
		snmp_free_pdu(pdu);
		state->running = 0;
	    }
	}
	state->waiting = 1;	

	numfds = 0;
	FD_ZERO(&fdset);
	block = 1;
	tvp = &timeout;
	timerclear(tvp);
	snmp_select_info(&numfds, &fdset, tvp, &block);
	if (block == 1)
	    tvp = NULL;	/* block without timeout */
	count = select(numfds, &fdset, 0, 0, tvp);
	if (count > 0){
		snmp_read(&fdset);
	} else switch(count){
	    case 0:
		snmp_timeout();
		break;
	    case -1:
		if (errno == EINTR){
		    continue;
		} else {
		    perror("select");
		}
	    default:
		printf("select returned %d\n", count);
	}
    }
}

