#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmpwalk.c,v 1.2 1992/07/29 18:17:20 djw Exp $";
#endif

/*
 * snmpwalk.c - send snmp GETNEXT requests to a network entity, walking a subtree.
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
#include <stdio.h>

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"

oid objid_mib[] = {1, 3, 6, 1, 2, 1};

int	snmp_dump_packet = 0;


main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session	session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int	arg;
    char *gateway = NULL;
    char *community = NULL;
    int gotroot = 0;
    oid	name[32];
    int name_length;
    oid root[MAX_NAME_LEN];
    int	rootlen, count;
    int running;
    int status;

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
	    rootlen = MAX_NAME_LEN;
	    if (read_objid(argv[arg], root, &rootlen)){
		gotroot = 1;
	    } else {
		printf("Invalid object identifier: %s\n", argv[arg]);
	    }
	}
    }

    if (gotroot == 0){
	bcopy((char *)objid_mib, (char *)root, sizeof(objid_mib));
	rootlen = sizeof(objid_mib) / sizeof(oid);
	gotroot = 1;
    }

    if (!(gateway && community && gotroot == 1)){
	printf("usage: snmpwalk [-d] gateway-name community-name [object-identifier]\n");
	exit(1);
    }

    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = gateway;
    session.community = (u_char *)community;
    session.community_len = strlen((char *)community);
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.authenticator = NULL;
    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
	printf("Couldn't open snmp\n");
	exit(-1);
    }

    bcopy((char *)root, (char *)name, rootlen * sizeof(oid));
    name_length = rootlen;

    running = 1;
    while(running){
	running = 0;
	pdu = snmp_pdu_create(GETNEXT_REQ_MSG);

	snmp_add_null_var(pdu, name, name_length);

	status = snmp_synch_response(ss, pdu, &response);
	if (status == STAT_SUCCESS){
	    if (response->errstat == SNMP_ERR_NOERROR){
		for(vars = response->variables; vars; vars = vars->next_variable){
		    if (vars->name_length < rootlen || bcmp(root, vars->name, rootlen * sizeof(oid)))
			continue;	/* not part of this subtree */
		    print_variable(vars->name, vars->name_length, vars);
		    bcopy((char *)vars->name, (char *)name, vars->name_length * sizeof(oid));
		    name_length = vars->name_length;
		    running = 1; /* restart so we can get next variable */
		}
	    } else {
		if (response->errstat == SNMP_ERR_NOSUCHNAME){
		    printf("End of MIB.\n");
		} else {
		    printf("Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
		    if (response->errstat == SNMP_ERR_NOSUCHNAME){
			printf("The request for this object identifier failed: ");
			for(count = 1, vars = response->variables; vars && count != response->errindex;
			    vars = vars->next_variable, count++)
				;
			if (vars)
			    print_objid(vars->name, vars->name_length);
			printf("\n");
		    }
		}
	    }

	} else if (status == STAT_TIMEOUT){
	    printf("No Response from %s\n", gateway);
	} else {    /* status == STAT_ERROR */
	    printf("An error occurred, Quitting\n");
	}

	if (response)
	    snmp_free_pdu(response);
    }
    snmp_close(ss);
}

