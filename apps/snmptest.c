#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmptest.c,v 1.2 1992/07/29 18:17:06 djw Exp $";
#endif

/*
 * snmptest.c - send snmp requests to a network entity.
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
#include <ctype.h>
#include <errno.h>

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"

extern int  errno;
int command = GET_REQ_MSG;
int	snmp_dump_packet = 0;

main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars, *vp;
    int	arg, ret;
    char *gateway = NULL;
    char *community = NULL;
    int	    status, count;

    init_mib();
    /*
     * usage: snmptest gateway-name community-name
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
		case 'd':
		    snmp_dump_packet++;
		    break;
		default:
		    fprintf(stderr, "invalid option: -%c\n", argv[arg][1]);
		    break;
	    }
	    continue;
	}
	if (gateway == NULL){
	    gateway = argv[arg];
	} else if (community == NULL){
	    community = argv[arg]; 
	} else {
	    fprintf(stderr, "usage: snmptest gateway-name community-name\n");
	    exit(1);
	}
    }
    if (community == NULL)
	community = "public";	/* default to public */

    if (!(gateway && community)){
	fprintf(stderr, "usage: snmptest gateway-name [community-name]\n");
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
	fprintf(stderr, "Couldn't open snmp\n");
	exit(-1);
    }

    while(1){
	vars = NULL;
	for(ret = 1; ret != 0;){
	    vp = (struct variable_list *)malloc(sizeof(struct variable_list));
	    vp->next_variable = NULL;
	    vp->name = NULL;
	    vp->val.string = NULL;

	    while((ret = input_variable(vp)) == -1)
		;
	    if (ret == 1){
		/* add it to the list */
		if (vars == NULL){
		    /* if first variable */
		    pdu = snmp_pdu_create(command);
		    pdu->variables = vp;
		} else {
		    vars->next_variable = vp;
		}
		vars = vp;
	    } else {
		/* free the last (unused) variable */
		if (vp->name)
		    free((char *)vp->name);
		if (vp->val.string)
		    free((char *)vp->val.string);
		free((char *)vp);
	    }
	}
	status = snmp_synch_response(ss, pdu, &response);
	if (status == STAT_SUCCESS){
	    switch(response->command){
		case GET_REQ_MSG:
		    printf("Received GET REQUEST ");
		    break;
		case GETNEXT_REQ_MSG:
		    printf("Received GETNEXT REQUEST ");
		    break;
		case GET_RSP_MSG:
		    printf("Received GET RESPONSE ");
		    break;
		case SET_REQ_MSG:
		    printf("Received SET REQUEST ");
		    break;
		case TRP_REQ_MSG:
		    printf("Received TRAP REQUEST ");
		    break;
	    }
	    printf("from %s\n", inet_ntoa(response->address.sin_addr));
	    printf("requestid 0x%x errstat 0x%x errindex 0x%x\n",
		response->reqid, response->errstat, response->errindex);
	    if (response->errstat == SNMP_ERR_NOERROR){
		for(vars = response->variables; vars; vars = vars->next_variable)
		    print_variable(vars->name, vars->name_length, vars);
	    } else {
		fprintf(stderr, "Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
		if (response->errstat == SNMP_ERR_NOSUCHNAME){
		    for(count = 1, vars = response->variables; vars && count != response->errindex;
			vars = vars->next_variable, count++)
			    ;
		    if (vars){
			printf("This name doesn't exist: ");
			print_objid(vars->name, vars->name_length);
		    }
		    printf("\n");
		}
	    }

	} else if (status == STAT_TIMEOUT){
	    fprintf(stderr, "No Response from %s\n", gateway);
	} else {    /* status == STAT_ERROR */
	    fprintf(stderr, "An error occurred, Quitting\n");
	}

	if (response)
	    snmp_free_pdu(response);
    }
}

int
ascii_to_binary(cp, bufp)
    u_char  *cp;
    u_char *bufp;
{
    int	subidentifier;
    u_char *bp = bufp;

    for(; *cp != '\0'; cp++){
	if (isspace(*cp))
	    continue;
	if (!isdigit(*cp)){
	    fprintf(stderr, "Input error\n");
	    return -1;
	}
	subidentifier = atoi(cp);
	if (subidentifier > 255){
	    fprintf(stderr, "subidentifier %d is too large ( > 255)\n", subidentifier);
	    return -1;
	}
	*bp++ = (u_char)subidentifier;
	while(isdigit(*cp))
	    cp++;
	cp--;
    }
    return bp - bufp;
}


int
hex_to_binary(cp, bufp)
    u_char  *cp;
    u_char *bufp;
{
    int	subidentifier;
    u_char *bp = bufp;

    for(; *cp != '\0'; cp++){
	if (isspace(*cp))
	    continue;
	if (!isxdigit(*cp)){
	    fprintf(stderr, "Input error\n");
	    return -1;
	}
	sscanf(cp, "%x", &subidentifier);
	if (subidentifier > 255){
	    fprintf(stderr, "subidentifier %d is too large ( > 255)\n", subidentifier);
	    return -1;
	}
	*bp++ = (u_char)subidentifier;
	while(isxdigit(*cp))
	    cp++;
	cp--;
    }
    return bp - bufp;
}


input_variable(vp)
    struct variable_list    *vp;
{
    u_char  buf[256], value[256], ch;

    printf("Please enter the variable name: ");
    fflush(stdout);
    if (gets(buf) == NULL)
	exit(0);

    if (*buf == 0){
	vp->name_length = 0;
	return 0;
    }
    if (*buf == '$'){
	switch(buf[1]){
	    case 'G':
		command = GET_REQ_MSG;
		printf("Request type is GET REQUEST\n");
		break;
	    case 'N':
		command = GETNEXT_REQ_MSG;
		printf("Request type is GETNEXT REQUEST\n");
		break;
	    case 'S':
		command = SET_REQ_MSG;
		printf("Request type is SET REQUEST\n");
		break;
	    case 'D':
		if (snmp_dump_packet){
		    snmp_dump_packet = 0;
		    printf("Turned packet dump off\n");
		} else {
		    snmp_dump_packet = 1;
		    printf("Turned packet dump on\n");
		}
		break;
	    case 'Q':
		printf("Quitting,  Goodbye\n");
		exit(0);
		break;
	    default:
		fprintf(stderr, "Bad command\n");
	}
	return -1;
    }
    vp->name_length = MAX_NAME_LEN;
    if (!read_objid(buf, value, &vp->name_length))
	return -1;
    vp->name = (oid *)malloc(vp->name_length * sizeof(oid));
    bcopy((char *)value, (char *)vp->name, vp->name_length * sizeof(oid));

    if (command == SET_REQ_MSG){
	printf("Please enter variable type [i|s|x|d|n|o|t|a]: ");
	fflush(stdout);
	if (gets(buf) == NULL)
	    exit(0);
	ch = *buf;
	switch(ch){
	    case 'i':
		vp->type = INTEGER;
		break;
	    case 's':
		vp->type = STRING;
		break;
	    case 'x':
		vp->type = STRING;
		break;
	    case 'd':
		vp->type = STRING;
		break;
	    case 'n':
		vp->type = NULLOBJ;
		break;
	    case 'o':
		vp->type = OBJID;
		break;
	    case 't':
		vp->type = TIMETICKS;
		break;
	    case 'a':
		vp->type = IPADDRESS;
		break;
	    default:
		fprintf(stderr, "bad type \"%c\", use \"i\", \"s\", \"x\", \"d\", \"n\", \"o\", \"t\", or \"a\".\n", *buf);
		return -1;
	}
	printf("Please enter new value: "); fflush(stdout);
	if (gets(buf) == NULL)
	    exit(0);
	switch(vp->type){
	    case INTEGER:
		vp->val.integer = (long *)malloc(sizeof(long));
		*(vp->val.integer) = atoi(buf);
		vp->val_len = sizeof(long);
		break;
	    case STRING:
		if (ch == 'd'){
		    vp->val_len = ascii_to_binary(buf, value);
		} else if (ch == 's'){
		    strcpy(value, buf);
		    vp->val_len = strlen(buf);
		} else if (ch == 'x'){
		    vp->val_len = hex_to_binary(buf, value);
		}
		vp->val.string = (u_char *)malloc(vp->val_len);
		bcopy((char *)value, (char *)vp->val.string, vp->val_len);
		break;
	    case NULLOBJ:
		vp->val_len = 0;
		vp->val.string = NULL;
		break;
	    case OBJID:
		vp->val_len = MAX_NAME_LEN;;
		read_objid(buf, value, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)malloc(vp->val_len);
		bcopy((char *)value, (char *)vp->val.objid, vp->val_len);
		break;
	    case TIMETICKS:
		vp->val.integer = (long *)malloc(sizeof(long));
		*(vp->val.integer) = atoi(buf);
		vp->val_len = sizeof(long);
		break;
	    case IPADDRESS:
		vp->val.integer = (long *)malloc(sizeof(long));
		*(vp->val.integer) = inet_addr(buf);
		vp->val_len = sizeof(long);
		break;
	    default:
		fprintf(stderr, "Internal error\n");
		break;
	}
    } else {	/* some form of get message */
	vp->type = NULLOBJ;
	vp->val_len = 0;
    }
    return 1;
}

