/*
   snmproute.c - Return lots of route information about a single SNMP route

******************************************************************
	Baseline Code Copyright 1988, 1989 by Carnegie Mellon University
	Additions Copyright 1991 by Bolt Beranek and Newman Inc.
		Primary Author:  David Waitzman at BBN

Carnegie Mellon University copyright notice:
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
#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmproute.c,v 1.3 1996/11/14 15:16:13 tpt2 Exp $";
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>
/*#include <strings.h>*/

#include "snmp.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "snmp_api.h"
#include "mib.h"

extern char *malloc();

/*
 * Configuration constants:
 */
#define BASE_TIMEOUT	40000
#define MAX_DESTS	4
#define HOSTNAMELEN	255

#define IS    ==
#define ISNT  !=
#define NOT   !
#define VV    (void)

/* globals */
int	snmp_dump_packet = 0;

/*oid	oid_sysDescr[]	= {1, 3, 6, 1, 2, 1, 1, 1, 0};*/
/*int	len_sysDescr = sizeof(oid_sysDescr)/sizeof(oid);*/
oid	oid_sysName[]		= {1, 3, 6, 1, 2, 1, 1, 5, 0};
int	len_sysName = sizeof(oid_sysName)/sizeof(oid);
oid	oid_ipRouteDest[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 1, 0, 0, 0, 0};
int	len_ipRouteDest = sizeof(oid_ipRouteDest)/sizeof(oid);
	/* IpAddress */
oid	oid_ipRouteIfIndex[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 2, 0, 0, 0, 0};
int     len_ipRouteIfIndex = sizeof(oid_ipRouteIfIndex)/sizeof(oid);
	/* INTEGER */
oid	oid_ipRouteMetric1[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 3, 0, 0, 0, 0};
int     len_ipRouteMetric1 = sizeof(oid_ipRouteMetric1)/sizeof(oid);
	/* INTEGER */
oid	oid_ipRouteMetric2[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 4, 0, 0, 0, 0};
int     len_ipRouteMetric2 = sizeof(oid_ipRouteMetric2)/sizeof(oid);
	/* INTEGER */
oid	oid_ipRouteMetric3[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 5, 0, 0, 0, 0};
int     len_ipRouteMetric3 = sizeof(oid_ipRouteMetric3)/sizeof(oid);
	/* INTEGER */
oid	oid_ipRouteMetric4[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 6, 0, 0, 0, 0};
int     len_ipRouteMetric4 = sizeof(oid_ipRouteMetric4)/sizeof(oid);
	/* INTEGER */
oid	oid_ipRouteNextHop[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 7, 0, 0, 0, 0};
int     len_ipRouteNextHop = sizeof(oid_ipRouteNextHop)/sizeof(oid);
	/* IpAddress */
oid	oid_ipRouteType[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 8, 0, 0, 0, 0};
int     len_ipRouteType = sizeof(oid_ipRouteType)/sizeof(oid);
	/* INTEGER */
oid	oid_ipRouteProto[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 9, 0, 0, 0, 0};
int     len_ipRouteProto = sizeof(oid_ipRouteProto)/sizeof(oid);
	/* INTEGER */
oid	oid_ipRouteAge[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 10, 0, 0, 0, 0};
int     len_ipRouteAge = sizeof(oid_ipRouteAge)/sizeof(oid);
	/* INTEGER */
oid	oid_ipRouteMask[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 11, 0, 0, 0, 0};
int     len_ipRouteMask = sizeof(oid_ipRouteMask)/sizeof(oid);
	/* IpAddress */
oid	oid_ipRouteMetric5[]	= {1, 3, 6, 1, 2, 1, 4, 21, 1, 12, 0, 0, 0, 0};
int     len_ipRouteMetric5 = sizeof(oid_ipRouteMetric4)/sizeof(oid);
	/* INTEGER */

char   *program_name = "";	/* from argv[0] */

u_long	next_hop_id;		/* set by cb_nexthop() */
u_long	actual_dest_id;		/* set by cb_actual_dest() */
long	session_timeout = BASE_TIMEOUT;
int	short_output = FALSE;
int	trace_path = FALSE;
int	pdu_type;

#define NUM_PREDEFINED_COMMUNITIES   4
#define MAX_COMMUNITIES		     (NUM_PREDEFINED_COMMUNITIES + 10)

char *communities[MAX_COMMUNITIES] =
{
    /* Note: Increase the NUM_PREDEFINED_COMMUNITIES constant as needed */
     "public", "lookatit", "private", "monitor"
};

u_int   num_current_communities = NUM_PREDEFINED_COMMUNITIES;
u_int   community_in_use_index = 0;
u_int   community_limit = 0;

typedef enum { ad_get = 1, ad_getnext } AD_TYPE;

typedef struct a_dest
{
    AD_TYPE ad_type;		/* use GET or GETNEXT operation */
    u_long  dest_id;
    char    dest_name[HOSTNAMELEN];
} A_DEST, *A_DESTP;


char *inet_ultoa(ul)
    u_long ul;
{
    struct in_addr in;
    in.s_addr = ul;
    return (inet_ntoa(in));    
}

void store_ip_addr(addr_bytesp, oidp, oid_length)
    register u_char *addr_bytesp; /* (I) 4 bytes long */
    oid	   *oidp;		  /* (M) */
    int	    oid_length;		  /* (I) */
{
    register oid *movingp = &oidp[oid_length - 4];
    assert(oid_length > 4);

    *movingp++ = *addr_bytesp++;
    *movingp++ = *addr_bytesp++;
    *movingp++ = *addr_bytesp++;
    *movingp++ = *addr_bytesp++;
}

void store_destination(dest_arr)
    register u_char *dest_arr; /* (I) 4 bytes long */
{
    store_ip_addr(dest_arr, oid_ipRouteDest, len_ipRouteDest);
    store_ip_addr(dest_arr, oid_ipRouteIfIndex, len_ipRouteIfIndex);
    store_ip_addr(dest_arr, oid_ipRouteMetric1, len_ipRouteMetric1);
    store_ip_addr(dest_arr, oid_ipRouteMetric2, len_ipRouteMetric2);
    store_ip_addr(dest_arr, oid_ipRouteMetric3, len_ipRouteMetric3);
    store_ip_addr(dest_arr, oid_ipRouteMetric4, len_ipRouteMetric4);
    store_ip_addr(dest_arr, oid_ipRouteNextHop, len_ipRouteNextHop);
    store_ip_addr(dest_arr, oid_ipRouteType, len_ipRouteType);
    store_ip_addr(dest_arr, oid_ipRouteProto, len_ipRouteProto);
    store_ip_addr(dest_arr, oid_ipRouteAge, len_ipRouteAge);
    store_ip_addr(dest_arr, oid_ipRouteMask, len_ipRouteMask);
    store_ip_addr(dest_arr, oid_ipRouteMetric5, len_ipRouteMetric5);
}

/*
 * Get the ip address for a hostname, if the hostname isn't in address form
 * already.
 * "kallisti.bbn.com" => 128.89.0.250
 * "128.89.0.250" => 128.89.0.250
 */
void must_get_name(hostname, addrp)
    char   *hostname;
    u_long *addrp;
{
    struct hostent *hp;

    *addrp = inet_addr(hostname);
    if (-1 IS (long)*addrp)
    {
	hp = gethostbyname(hostname);
	if (hp IS NULL)
	{
	    printf("%s: unknown name- %s\n", program_name, hostname);
	    exit(1);
	}
	else
	    bcopy((char *)hp->h_addr, (char *)addrp, hp->h_length);
    }
}

void community_dump()
{
    u_int i;
    printf("\nCommunities:\n");
    for (i = 0; i < num_current_communities; i++)
	printf("\t\"%s\"\n", communities[i]);
    printf("\n");
}


void community_add(cnamep)
    char *cnamep;
{
    assert(num_current_communities > 1);

    if (num_current_communities < MAX_COMMUNITIES)
    {
	/*
	 * if this is the first community added on the command-line,
	 * then use it as the first community when xmitting.
	 */
	if (community_in_use_index IS 0)
	    community_in_use_index = num_current_communities;

	communities[num_current_communities++] = cnamep;
    }
    else
	printf(
"Too many communities specified, ignoring %s\n\
To remedy: increase the internal MAX_COMMUNITIES constant\n", cnamep);
}

void community_reset_new_router(ssp)
    struct snmp_session *ssp;
{
    int clen = strlen(communities[community_in_use_index]);

    community_limit = 0;	/* reset the limit of # communities tried */

    if (ssp->community_len ISNT clen + 1)
    {
	free(ssp->community);
	ssp->community = (u_char *)malloc(clen + 1);
	assert(ssp->community);
	ssp->community_len = clen;
    }

    strcpy(ssp->community, communities[community_in_use_index]);

#if 0
    printf("First trying with community %s\n", ssp->community);
#endif /* 0 */
}

void community_switch(ssp)
    struct snmp_session *ssp;
{
    int clen;

    /*
     * If the community limit counter becomes equal to number of currently
     * defined communities, then every community has been tried for the
     * current router.  That means that the router doesn't respond to
     * anything we sent, and is probably down or not an SNMP router.
     */
    if (++community_limit IS num_current_communities)
    {
	printf("No Response from %s\n", ssp->peername);
	exit(1);
    }

    community_in_use_index++;
    if (community_in_use_index IS num_current_communities)
	community_in_use_index = 0;

    clen = strlen(communities[community_in_use_index]);

    if (ssp->community_len ISNT clen + 1)
    {
	free(ssp->community);
	ssp->community = (u_char *)malloc(clen + 1);
	assert(ssp->community);
	ssp->community_len = clen;
    }
    strcpy(ssp->community, communities[community_in_use_index]);

    printf("Retrying %s with community %s\n", ssp->peername, ssp->community);
}


typedef enum { proc_ok, proc_no_such_name, proc_other_err } proc_returns;

proc_returns proc_var(ssp, oidp, oid_length, namep, cbfunc, display_err)
    struct snmp_session *ssp;
    oid	                *oidp;	      /* (I) */
    int	                 oid_length;  /* (I) */
    char                *namep;	      /* (I) */
    void               (*cbfunc)();   /* (I) called with 1 argument
					 (struct variable_list *) */
    int			 display_err; /* (I) 1 to display message on an error 
					 or 0 to not to */
{
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int	    status;
    
  retry:
    pdu = snmp_pdu_create(pdu_type);
    snmp_add_null_var(pdu, oidp, oid_length);

    status = snmp_synch_response(ssp, pdu, &response);
    if (status IS STAT_SUCCESS)
    {
	if (response->errstat IS SNMP_ERR_NOERROR)
	{
	    vars = response->variables;
	    if (vars->name_length IS oid_length &&
		!bcmp((char *)oidp, (char*)vars->name, sizeof(oid_length)))
	    {
		printf("\t%12s = ", namep);
		print_value(oidp, oid_length, vars);
		if (cbfunc)
		    (*cbfunc)(vars);
		snmp_free_pdu(response);

		return (proc_ok);
	    }
	}
	else
	{
	    if (response->errstat IS SNMP_ERR_NOSUCHNAME)
	    {
		if (display_err)
		{
		    printf("Error in packet. %12s = doesn't exist\n", namep);
		    
		    vars = response->variables;
		    if (vars)
			print_objid(vars->name, vars->name_length);
		    printf("\n");
		}
		return (proc_no_such_name);
	    }
	    else
		printf("\tError in packet.  Reason: %s\n",
		       snmp_errstring(response->errstat));

	    snmp_free_pdu(response);
	    
	    return (proc_other_err);
	}
    }
    else if (status IS STAT_TIMEOUT)
    {
	community_switch(ssp);
	goto retry;
    }
    else
    {    /* status IS STAT_ERROR */
	printf("An error occurred, Quitting\n");
	exit(2);
    }
/*NOTREACHED*/
}

/*
 * Callback function used to set the next hop to go to.
 */
void cb_nexthop(vars)
    struct variable_list *vars;
{
    bcopy(vars->val.string, &next_hop_id, sizeof(next_hop_id));
}

/*
 * Callback function used to set the actual destination.
 */
void cb_actual_dest(vars)
    struct variable_list *vars;
{
    bcopy(vars->val.string, &actual_dest_id, sizeof(next_hop_id));
}


char *examine_router(router_name, num_dests, dests)
    char   *router_name;
    u_int   num_dests;
    A_DEST  dests[MAX_DESTS];
{
    struct snmp_session session;
    struct snmp_session *ssp;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    char    val_sysName[256];
    u_long  router_id;
    u_char  dest_arr[4];
    int	    status;
    int	    di;			/* Destination loop Index */
    struct hostent *hp;
    proc_returns pret;

    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = router_name;
    session.retries = 6;
    session.timeout = session_timeout;
    session.authenticator = NULL;
    snmp_synch_setup(&session);
    ssp = snmp_open(&session);
    if (ssp IS NULL)
    {
	printf("%s: snmp_open() failed\n", program_name);
	exit(1);
    }

    community_reset_new_router(ssp);

    must_get_name(session.peername, &router_id);

  retry:
    pdu = snmp_pdu_create(GET_REQ_MSG);
    snmp_add_null_var(pdu, oid_sysName, len_sysName);

    status = snmp_synch_response(ssp, pdu, &response);
    if (status IS STAT_SUCCESS)
    {
	if (response->errstat IS SNMP_ERR_NOERROR)
	{
	    vars = response->variables;
	    if (vars->name_length IS len_sysName &&
		!bcmp((char *)oid_sysName, (char*)vars->name,
		      sizeof(oid_sysName)))
	    {
		bcopy((char *)vars->val.string, val_sysName,
		      vars->val_len);
		val_sysName[vars->val_len] = '\0';
	    }
	}
	else
	{
	    hp = gethostbyaddr((char *)&router_id, sizeof(router_id), AF_INET);
	    if (hp ISNT NULL)
		strcpy(val_sysName, hp->h_name);
	    else
		sprintf(val_sysName, "[%s]", router_name);
	}
    }
    else if (status IS STAT_TIMEOUT)
    {
	community_switch(ssp);
	goto retry;
    }
    else
    {    /* status IS STAT_ERROR */
	printf("An error occurred, Quitting\n");
	exit(2);
    }
    
    if (response)
	snmp_free_pdu(response);

    printf("\nName \"%s\"\n", val_sysName);
    printf("\tAddress   %s\n", inet_ultoa(router_id));
    printf("\tCommunity \"%s\"\n", ssp->community);

    
    for (di = 0; di < num_dests; di++)
    {
	if (di > 0)
	    printf("Trying alternate destination %s\n", dests[di].dest_name);

	bcopy(&dests[di].dest_id, dest_arr, sizeof(dests[di].dest_id));
	store_destination(dest_arr);

	if (dests[di].ad_type IS ad_get)
	    pdu_type = GET_REQ_MSG;
	else
	    pdu_type = GETNEXT_REQ_MSG;

	pret = proc_var(ssp, oid_ipRouteDest, len_ipRouteDest, "Destination",
			cb_actual_dest, 0);
	if (pret IS proc_ok)
	    break;
    }
    
    if (pret ISNT proc_ok)
    {
	printf("No route exists to any of the specified destinations.\n");
	return (NULL);
    }
	

    VV proc_var(ssp, oid_ipRouteNextHop, len_ipRouteNextHop, "NextHop",
		cb_nexthop, 1);
    VV proc_var(ssp, oid_ipRouteType, len_ipRouteType, "Type", 0, 1);
    VV proc_var(ssp, oid_ipRouteProto, len_ipRouteProto, "Proto", 0, 1);
    
    if (short_output IS FALSE)
    {
	VV proc_var(ssp, oid_ipRouteIfIndex, len_ipRouteIfIndex, "IfIndex", 0,1);
	VV proc_var(ssp, oid_ipRouteAge, len_ipRouteAge, "Age", 0,1);
	VV proc_var(ssp, oid_ipRouteMetric1, len_ipRouteMetric1, "Metric1", 0,1);
	VV proc_var(ssp, oid_ipRouteMetric2, len_ipRouteMetric2, "Metric2", 0,0);
	VV proc_var(ssp, oid_ipRouteMetric3, len_ipRouteMetric3, "Metric3", 0,0);
	VV proc_var(ssp, oid_ipRouteMetric4, len_ipRouteMetric4, "Metric4", 0,0);
	VV proc_var(ssp, oid_ipRouteMetric5, len_ipRouteMetric5, "Metric5", 0,0);
	VV proc_var(ssp, oid_ipRouteMask, len_ipRouteMask, "Mask", 0,0);
    }

    if (trace_path)
    {
	/* Test if the place to stop */
	if (   next_hop_id IS 0		  /* illegal */
  	    || next_hop_id IS dests[0].dest_id /* primary reached dest. */
	    || next_hop_id IS router_id)  /* in an apparent routing loop */
	{
	    printf("Normal end of trace\n");
	    return (NULL);
	}
	router_name = inet_ultoa(next_hop_id);
	return (router_name);
    }
    else
	return (NULL);
}


void add_dest(num_destsp, dests, ad_type, dest_arg)
    u_int   *num_destsp;
    A_DEST   dests[MAX_DESTS];
    AD_TYPE  ad_type;
    char    *dest_arg;
{
    if (*num_destsp IS MAX_DESTS)
    {
	printf("%s: Too many destinations specified, ignoring %s\n", 
		program_name, dest_arg);
	return;
    }
    strncat(dests[*num_destsp].dest_name, dest_arg,
	    sizeof(dests[*num_destsp].dest_name));
    must_get_name(dests[*num_destsp].dest_name,
		  &dests[*num_destsp].dest_id);
    dests[*num_destsp].ad_type = ad_type;
    (*num_destsp)++;
}




void usage_error()
{
    printf("\
Usage: %s router-name\n\
\t[-g route-dest]     Use GET on this address (repeatable)\n\
\t[-n route-dest]     Use GET-NEXT on this address (repeatable)\n\
\t[-c community-name] Specifies more community names (repeatable)\n\
\t[-s]                Short output\n\
\t[-t]                Trace the routing path\n\
\t[-L]                Long path/high time-out mode (repeatable)\n\
\t[-d]                Dump SNMP packets\n\n\
\tYou must provide at least one -g or -n option."
, program_name);

    community_dump();
    exit(1);
/*NOTREACHED*/
}


int main(argc, argv)
    int	    argc;
    char    *argv[];
{
    char   *router_name = NULL;
    int	    arg;
    u_int   num_dests = 0;
    A_DEST  dests[MAX_DESTS];

    init_mib();
    program_name = argv[0];

    /* Parse arguments */
    for (arg = 1; arg < argc; arg++)
    {
	if (argv[arg][0] IS '-')
	{
	    switch(argv[arg][1])
	    {
	      case 'g':
		++arg;
		if (arg IS argc)
		    usage_error();
		add_dest(&num_dests, dests, ad_get, argv[arg]);
		break;

	      case 'n':
		++arg;
		if (arg IS argc)
		    usage_error();
		add_dest(&num_dests, dests, ad_getnext, argv[arg]);
		break;

	      case 'd':
		snmp_dump_packet++;
		break;

	      case 's':
		short_output = TRUE;
		break;

	      case 't':
		trace_path = TRUE;
		break;

	      case 'L':
		session_timeout = 2 * session_timeout; /* a longer timeout */
		break;

	      case 'c':
		++arg;
		if (arg IS argc)
		    usage_error();
		community_add(argv[arg]);
		break;

	      default:
		printf("invalid option: -%c\n", argv[arg][1]);
		usage_error();
		break;

	    }
	    continue;
	} /* if */

	if (router_name IS NULL)
	    router_name = argv[arg];
	else
	{
	    printf("Error- extra stuff on the command line\n");
	    usage_error();
	}
    } /* for */

    if (router_name IS NULL || num_dests IS 0)
	usage_error();

    do
	router_name = examine_router(router_name, num_dests, dests);
    while (router_name);

    return (0);
}
