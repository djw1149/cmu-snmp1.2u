#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmpfind.c,v 1.2 1992/07/29 18:16:50 djw Exp $";
#endif

/*
 * snmpfind.c - Find snmp speaking devices via broadcast-- DANGEROUS!
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

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
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
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

typedef long    fd_mask;

#ifndef FD_SET
#define NFDBITS (sizeof(fd_mask) * NBBY)        /* bits per mask */
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif
#endif

extern int  errno;
int	snmp_dump_packet = 0;
struct state {
    int running;
} state_info;

snmp_input(op,  session, reqid, pdu, magic)
    int op;
    struct snmp_session *session;
    int reqid;
    struct snmp_pdu *pdu;
    void *magic;
{
    struct variable_list *vars;
    struct state *state = (struct state *)magic;
    int count;

    if (op == RECEIVED_MESSAGE && pdu->command == GET_RSP_MSG){
        printf("%s: ", inet_ntoa(pdu->address.sin_addr));
        if (pdu->errstat == SNMP_ERR_NOERROR){
            for(vars = pdu->variables; vars; vars = vars->next_variable)
                print_value(vars->name, vars->name_length, vars);
        } else {
	  if (pdu->errstat == SNMP_ERR_NOSUCHNAME){
	    printf("Variable not found\n");
	  } else {
	    printf("Error in packet\n");
	  }
        }
    } else if (op == TIMED_OUT){
        /* We don't restart on timeout so main will exit */
        printf("Timed Out\n");
	state->running = 0;
    }
    return 0;
}


main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int	arg;
    char *gateway = NULL;
    char *community = NULL;
    int	count, current_name = 0;
    char *names[128];
    oid name[MAX_NAME_LEN];
    int name_length;
    int status;
    int numfds, block;
    fd_set fdset;
    struct timeval timeout, *tvp;
    struct state *state = &state_info;

    init_mib();
    /*
     * usage: snmpfind gateway-name community-name variables
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
	    names[current_name++] = argv[arg];
	}
    }

    if (!(gateway && community && current_name > 0)){
	printf("usage: snmpfind address community-name object-identifier [object-identifier ...]\n");
	printf("The address should be a limited broadcast address.\n");
	printf("This is a DANGEROUS program!  It can load up your net.\n");
	exit(1);
    }

    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = gateway;
    session.community = (u_char *)community;
    session.community_len = strlen((char *)community);
    session.retries = 0;
    session.timeout = 20000000;
    session.authenticator = NULL;
    session.callback = snmp_input;
    session.callback_magic = (void *)state;
    ss = snmp_open(&session);
    if (ss == NULL){
	printf("Couldn't open snmp\n");
	exit(-1);
    }

    pdu = snmp_pdu_create(GET_REQ_MSG);

    state->running = 1;
    for(count = 0; count < current_name; count++){
	name_length = MAX_NAME_LEN;
	if (!read_objid(names[count], name, &name_length)){
	    printf("Invalid object identifier: %s\n", names[count]);
	}
	
	snmp_add_null_var(pdu, name, name_length);
    }

    if (snmp_send(ss, pdu) == 0){
      snmp_free_pdu(pdu);
      state->running = 0;
    }
    while(state->running){
        numfds = 0;
        FD_ZERO(&fdset);
        block = 1;
        tvp = &timeout;
        timerclear(tvp);
        snmp_select_info(&numfds, &fdset, tvp, &block);
        if (block == 1)
            tvp = NULL; /* block without timeout */
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

    snmp_close(ss);
    exit(0);
}

