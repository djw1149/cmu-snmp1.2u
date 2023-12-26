#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmparp.c,v 1.3 1996/11/14 15:16:11 tpt2 Exp $";
#endif

/*
 *	Copyright 1993 by SINTEF RUNIT
 *
 *	All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of SINTEF RUNIT not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * SINTEF RUNIT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SINTEF RUNIT BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Program to get and display the IP "ARP" table of an SNMP agent
 * implementing MIB-1 or MIB-2.  The MIB-2 ipNetToMediaTable is tried
 * first, if that fails the atTable will be tried.
 *
 * Havard.Eidnes@runit.sintef.no, 930704

Example of use:

% snmparp sintef-gw public 129.241.181
ARP Table
Name                    Address         Media-addr        Type      Interface
unit-gw.unit.no         129.241.181.1   aa:0:4:0:68:dc    dynamic   Fddi0
mtfs-gw.unit.no         129.241.181.3   aa:0:4:0:59:dd    dynamic   Fddi0
sintef-gw.sintef.no     129.241.181.4   0:0:c:3:3b:6a     other     Fddi0
termo-gw.unit.no        129.241.181.5   0:0:a2:3:43:ca    dynamic   Fddi0
Std.supernett.tele.no   129.241.181.6   0:0:a9:2:4:1f     dynamic   Fddi0
dragv-gw.unit.no        129.241.181.7   aa:0:4:0:7e:de    dynamic   Fddi0
ed-gw.unit.no           129.241.181.9   aa:0:4:0:fa:df    dynamic   Fddi0
% 

% snmparp sintef-gw public 129.241.1.5
ARP Table
Name                    Address         Media-addr        Type      Interface
runix.runit.sintef.no   129.241.1.5     8:0:20:9:44:bc    dynamic   Ethernet0
% 

With no prefix given, it dumps the whole ARP table.
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"


oid oid_ntomix[] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 1};

#define IF_NTOM_IFINDEX		1
#define IF_NTOM_PHYSADDRESS	2
#define IF_NTOM_NETADDRESS	3
#define IF_NTOM_TYPE		4

oid oid_atifix[] = {1, 3, 6, 1, 2, 1, 3, 1, 1, 1};

#define AT_IFINDEX		1
#define AT_PHYSADDRESS		2
#define AT_NETADDRESS		3

oid oid_cfg_nnets[] = {1, 3, 6, 1, 2, 1, 2, 1, 0};

oid oid_ifname[]    = {1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 0};

struct snmp_session *Session;
oid match_prefix[40];
int match_prefix_length;
oid prefix[4];
int prefix_len = 0;
char *progname;
int ifnum;
int max_ifix;
int snmp_dump_packet = 0;

int hflag;			/* No header? */
int nflag;			/* No names? */


extern char* strchr();

#define min(a,b)	(a<b ? a : b)

#define MAXIFS 40

struct ifinfo {
    char	*name;
} ifinfo[MAXIFS];



get_snmp_response_std(request,response)
    struct snmp_pdu *request, **response;
{
    int status;

    status = snmp_synch_response(Session, request, response);
    if (status != STAT_SUCCESS)
    {
	fprintf(stderr, "SNMP request failed:");
	if(status == STAT_TIMEOUT)
	    fprintf(stderr, " Request timeout\n");
	else
	    fprintf(stderr, " status %d\n", status);
	return -1;
    }
    if ((*response)->errstat != SNMP_ERR_NOERROR)
    {
	fprintf(stderr, "SNMP request failed: %s\n",
		snmp_errstring((*response)->errstat));
	return -1;
    }
    return 0;
}


/*
 * Remove spaces from interface name...
 */

fixup_name(name)
     char *name;
{
    char *cp;

    for(cp = name; *cp; cp++)
    {
	if(*cp == ' ')
	    *cp = '-';
    }
}


extract_if_names(response)
    struct snmp_pdu *response;
{
    struct variable_list *vp;
    int ix;

    for (vp = response->variables; vp; vp = vp->next_variable)
    {
	if (!bcmp((char*)vp->name,
		  (char*)oid_ifname,
		  sizeof(oid_ifname) - sizeof(oid))
	    ) 
	{
	    ix = vp->name[10];
	    ifinfo[ix].name = (char*)malloc(vp->val_len + 1);
	    bcopy((char*)vp->val.string, ifinfo[ix].name, vp->val_len);
	    ifinfo[ix].name[vp->val_len] = 0;
	    fixup_name(ifinfo[ix].name);
	}
	else
	{
	    fprintf(stderr, "extract_if_names: wrong variable?!\n");
	}
    }
}


#ifdef ALL_AT_ONCE
get_if_names()
{
    struct snmp_pdu *request, *response;
    oid variable[100], *instance;
    int variable_len;
    int intf, i;

    for(intf = 1; intf < max_ifix; intf+=8)
    {
	request = snmp_pdu_create(GET_REQ_MSG);
	bcopy((char *)oid_ifname, (char *)variable, sizeof(oid_ifname));
	variable_len = sizeof(oid_ifname) / sizeof(oid);
	instance = variable + 10;

	for(i = intf; i < min(intf+8, max_ifix+1); i++)
	{
	    *instance = i;
	    snmp_add_null_var(request, variable, variable_len);
	}
	if (get_snmp_response_std(request,&response) != 0)
	    break;
	extract_if_names(response);
    }
}
#else /* !ALL_AT_ONCE */
get_if_names()
{
    struct snmp_pdu *request, *response;
    struct variable_list *vp;

    request = snmp_pdu_create(GETNEXT_REQ_MSG);
    snmp_add_null_var(request, oid_ifname, sizeof(oid_ifname)/sizeof(oid));
    while(request)
    {
	if (get_snmp_response_std(request,&response) != 0)
	    break;
	vp = response->variables;
	if (bcmp((char*)vp->name, (char*)oid_ifname,
		 sizeof(oid_ifname)-sizeof(oid))) /* ran off end of if list? */
	{
	    break;
	}
	extract_if_names(response);

	request = snmp_pdu_create(GETNEXT_REQ_MSG); /* prepare for next qry */
	snmp_add_null_var(request, vp->name, vp->name_length);
    }
}
#endif /* ALL_AT_ONCE */



char *
arp_type(tp)
    int tp;
{
    switch (tp)
    {
    case 1:
	return "other";
    case 2:
	return "invalid";
    case 3:
	return "dynamic";
    case 4:
	return "static";
    default:
	return "*unknown*";
    }
}


int
agent_has_ip_net_to_media()
{
    struct snmp_pdu *request, *response;
    struct variable_list *vp;
    int varname_len;
    
    request = snmp_pdu_create(GETNEXT_REQ_MSG);

    varname_len = sizeof(oid_ntomix) / sizeof(oid);
    snmp_add_null_var(request, oid_ntomix, varname_len);

    if (get_snmp_response_std(request,&response) != 0)
	exit(1);

    vp = response->variables;
    return ! bcmp((char*)vp->name, (char*)oid_ntomix, sizeof(oid_ntomix));
}


init(request, base_oid, base_oid_len, last_byte)
    struct snmp_pdu *request;
    oid *base_oid;
    int base_oid_len, last_byte;
{
    oid variable[100];
    int variable_len;
    int i;

    variable_len = base_oid_len;
    bcopy((char*)base_oid, (char*)variable, base_oid_len * sizeof(oid));
    variable[variable_len-1] = last_byte;

    if (prefix_len == 0)
    {
	snmp_add_null_var(request, variable, variable_len);
    }
    else
    {
	variable[variable_len++] = ifnum;

	for (i = 0; i < prefix_len; i++)
	    variable[variable_len++] = prefix[i];
	variable[variable_len-1]--;
	for (i = prefix_len; i < 4; i++)
	    variable[variable_len++] = 255;

	snmp_add_null_var(request, variable, variable_len);
    }
}


#define INIT(base_oid, last_byte)	\
    init(request, base_oid, sizeof(base_oid) / sizeof(oid), last_byte)

int
init_ntom(request)
    struct snmp_pdu *request;
{
    INIT(oid_ntomix, IF_NTOM_IFINDEX);
    INIT(oid_ntomix, IF_NTOM_PHYSADDRESS);
    INIT(oid_ntomix, IF_NTOM_NETADDRESS);
    INIT(oid_ntomix, IF_NTOM_TYPE);
    bcopy((char*)oid_ntomix, (char*)match_prefix, sizeof(oid_ntomix));
    match_prefix_length = sizeof(oid_ntomix) / sizeof(oid) - 1;
}


int
init_at(request)
    struct snmp_pdu *request;
{
    INIT(oid_atifix, AT_IFINDEX);
    INIT(oid_atifix, AT_PHYSADDRESS);
    INIT(oid_atifix, AT_NETADDRESS);
    bcopy((char*)oid_atifix, (char*)match_prefix, sizeof(oid_atifix));
    match_prefix_length = sizeof(oid_atifix) / sizeof(oid) - 1;
}


char *
sprint_physaddress(phy, phy_len)
    char *phy;
    int phy_len;
{
    static char buf[100], *bp;
    u_char *cp;
    int i;

    cp = (u_char*)phy;
    if(phy_len == 6)
    {
	sprintf(buf, "%x:%x:%x:%x:%x:%x",
		*cp, *(cp+1), *(cp+2), *(cp+3), *(cp+4), *(cp+5));
    }else{
	bp = buf;
	for(i=0; i < phy_len; i++)
	{
	    sprintf(bp, "%x", *cp++);
	    bp += strlen(bp);
	    if (i != phy_len - 1)
		*bp++ = '.';
	}
	*bp = 0;
    }
    return buf;
}


/*
 * Request a variable with a GET REQUEST message on the given
 * session.  The session must have been opened as a synchronous
 * session (synch_setup_session()).  If the variable is found, a
 * pointer to a struct variable_list object will be returned.
 * Otherwise, NULL is returned.  The caller must free the returned
 * variable_list object when done with it.
 */
struct variable_list *
getvarbyname(sp, name, len)
    struct snmp_session *sp;
    oid	*name;
    int len;
{
    struct snmp_pdu *request, *response;
    struct variable_list *var = NULL, *vp;
    int status;
    
    request = snmp_pdu_create(GET_REQ_MSG);
    
    snmp_add_null_var(request, name, len);
    
    status = snmp_synch_response(sp, request, &response);
    
    if (status == STAT_SUCCESS){
	if (response->errstat == SNMP_ERR_NOERROR){
	    for(var = response->variables; var; var = var->next_variable){
		if (var->name_length == len &&
		    !bcmp(name, var->name, len * sizeof(oid))
		    )
		    break;	/* found our match */
	    }
	    if (var != NULL){
		/*
		 * Now unlink this var from pdu chain so it doesn't get freed.
		 * The caller will free the var.
		 */
		if (response->variables == var){
		    response->variables = var->next_variable;
		} else {
		    for(vp = response->variables; vp; vp = vp->next_variable){
			if (vp->next_variable == var){
			    vp->next_variable = var->next_variable;
			    break;
			}
		    }
		}
	    }
	}
    }
    return var;
}


char *
s_hostname(ina)
    struct in_addr ina;
{
    struct hostent *hp;

    hp = gethostbyaddr((char*)&ina, sizeof(ina), AF_INET);
    if (hp)
	return hp->h_name;
    else
	return "[?]";
}


print_heading(has_ntom)
    int has_ntom;
{
    printf("ARP Table\n");
    if (!nflag)
	printf("%-23s ", "Name");
    printf("%-15s %-17s ", "Address", "Media-addr");	   
    if (has_ntom)
	printf("%-9s ", "Type");
    printf("Interface\n");
}


struct info 
{
    int			ifindex;
    int			ifindex_set;
    char		physaddress[100];
    int			physaddress_len;
    int			physaddress_set;
    struct in_addr	netaddress;
    int			netaddress_len;
    int			netaddress_set;
    int			ntom_type;
    int			ntom_type_set;
} info;    


get_n_show_arp()
{
    struct snmp_pdu *request, *response;
    struct variable_list *vp;
    int status;
    struct variable_list *var;
#define NTOM	1
#define AT	2
    int ntom_or_at;
    int (*initfunc)();
    int type;

    var = getvarbyname(Session, oid_cfg_nnets,
		       sizeof(oid_cfg_nnets) / sizeof(oid));
    if (var)
	max_ifix = *var->val.integer;
    else
    {
	fprintf(stderr, "%s: didn't return number of interfaces\n",
		progname);
	exit(1);
    }
    get_if_names();		/* Get interface names */

    request = snmp_pdu_create(GETNEXT_REQ_MSG);

    if (agent_has_ip_net_to_media())
    {
	ntom_or_at = NTOM;
	init_ntom(request);
	initfunc = init_ntom;
    }else{
	ntom_or_at = AT;
	init_at(request);
	initfunc = init_at;
    }
    
    if (!hflag)
	print_heading(initfunc == init_ntom);

    while(request)
    {
    again:
	status = snmp_synch_response(Session, request, &response);
	if (status != STAT_SUCCESS)
	{
	    fprintf(stderr, "SNMP request failed:");
	    if(status == STAT_TIMEOUT)
		fprintf(stderr, " Request timeout\n");
	    else
		fprintf(stderr, " status %d\n", status);
	    break;
	}		    
	if (response->errstat != SNMP_ERR_NOERROR)
	{
	    fprintf(stderr, "SNMP request failed: %s\n",
		    snmp_errstring(response->errstat));
	    break;
	}

	request = NULL;
	bzero((char*)&info, sizeof(info));

	for (vp = response->variables; vp; vp = vp->next_variable)
	{
	    if (bcmp((char*)vp->name,
		     (char*)match_prefix,
		     match_prefix_length * sizeof(oid))
		)
		continue;	/* not right variable, just continue -- */
				/* will break out of loop eventually */
	    if (prefix_len != 0)
	    {
		oid *ip, *pp;
		int i;
		int intf;

		intf = vp->name[match_prefix_length+1];
				/* Compare instance with prefix */
		for(ip = &vp->name[match_prefix_length+2],
		    pp = prefix, i=0;
		    i < prefix_len;
		    ip++, pp++, i++)
		{
		    if (*ip != *pp) /* mismatch, not on this interface */
		    {
				/* Reinitialize query, try again */
			if (intf > ifnum)
			    ifnum = intf;
			else
			    ifnum++;
			if (ifnum > max_ifix)
			    return; /* no more interfaces */
			
			request = snmp_pdu_create(GETNEXT_REQ_MSG);
			initfunc(request);
			goto again;
		    }
		}
		ifnum = intf;	/* Match -- at this interface */
	    }
				/* At this point we are in the right */
				/* subtree (and have the right instance), */
				/* so add to request for next round of */
				/* get-next loop */
	    if (request == NULL)
		request = snmp_pdu_create(GETNEXT_REQ_MSG);
	    snmp_add_null_var(request, vp->name, vp->name_length);

	    type = vp->name[match_prefix_length];
	    switch(ntom_or_at)
	    {
	    case NTOM:
		type = vp->name[match_prefix_length];
		switch((char)type)
		{
		case IF_NTOM_IFINDEX:
		    info.ifindex = *vp->val.integer;
		    info.ifindex_set = 1;
		    break;
		case IF_NTOM_PHYSADDRESS:
		    bcopy((char*)vp->val.string,
			  (char*)info.physaddress,
			  vp->val_len);
		    info.physaddress_len = vp->val_len;
		    info.physaddress_set = 1;
		    break;
		case IF_NTOM_NETADDRESS:
		    bcopy((char*)vp->val.string,
			  (char*)&info.netaddress,
			  vp->val_len);
		    info.netaddress_len = vp->val_len;
		    info.netaddress_set = 1;
		    break;
		case IF_NTOM_TYPE:
		    info.ntom_type = *vp->val.integer;
		    info.ntom_type_set = 1;
		    break;
		}
		break;
	    case AT:
		switch((char)type)
		{
		case AT_IFINDEX:
		    info.ifindex = *vp->val.integer;
		    info.ifindex_set = 1;
		    break;
		case AT_PHYSADDRESS:
		    bcopy((char*)vp->val.string,
			  (char*)info.physaddress,
			  vp->val_len);
		    info.physaddress_len = vp->val_len;
		    info.physaddress_set = 1;
		    break;
		case AT_NETADDRESS:
		    bcopy((char*)vp->val.string,
			  (char*)&info.netaddress,
			  vp->val_len);
		    info.netaddress_len = vp->val_len;
		    info.netaddress_set = 1;
		    break;
		}
	    }
	}
	if (!(info.netaddress_set &&
	      info.physaddress_set &&
	      info.ifindex_set))
	{
	    if (request)
		snmp_free_pdu(request);
	    request = 0;
	    continue;
	}
	if (!nflag)
	{
	    printf("%-23.23s ", s_hostname(info.netaddress));
	}
	printf("%-15.15s ", inet_ntoa(info.netaddress));
	printf("%-17.17s ", sprint_physaddress(info.physaddress,
					       info.physaddress_len));
	if (info.ntom_type_set)
	    printf("%-9s ", arp_type(info.ntom_type));
	if (ifinfo[info.ifindex].name != 0)
	    printf("%s", ifinfo[info.ifindex].name);
	else
	    printf("interface-%d", info.ifindex);
	printf("\n");
    }
}


int
parse_prefix(pp)
    char *pp;
{
    char *dot;
    int i;

    dot = pp;
    do
    {
	if ((dot = strchr(pp,'.')) != NULL)
	    *dot = '\0';
	i = atoi(pp);
	if (i >= 0 && i <= 255 && prefix_len <= 4)
	    prefix[prefix_len++] = i;
	else
	    return -1;
	pp = dot + 1;
    }
    while (dot != NULL);
    for(i = prefix_len-1; i >= 0 && prefix[i] == 0; i--, prefix_len--);
    return 0;
}


usage()
{
    fprintf(stderr, "usage: %s agent community [-hn] [IP-prefix]\n", progname);
    exit(1);
}


int
main(argc, argv)
    int argc;
    char **argv;
{
    struct snmp_session session;
    char *host;
    char *community;
    int opt;
    extern int optind;

    progname = argv[0];
    argc--, argv++;
    if (!argc)
	usage();
    if (argc--)
	host = *argv++;
    if (argc--)
	community = *argv++;
    else
	usage();

    optind = 0;			/* We've fiddled with argc above. */
				/* I know, probably non-portable... */
    while((opt = getopt(argc, argv, "nh")) != -1)
    {
	switch(opt)
	{
	case 'h':
	    hflag++;
	    break;
	case 'n':
	    nflag++;
	    break;
	default:
	    usage();
	}
    }	
    if (optind < argc && isdigit(*argv[optind]))
    {
	if (parse_prefix(argv[optind]) != 0)
	    usage();
    }

    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = host;
    session.community = (u_char*) community;
    session.community_len = strlen(community);
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.authenticator = NULL;
    snmp_synch_setup(&session);
    Session = snmp_open(&session);

    if (Session == NULL){
	printf("Couldn't open snmp\n");
	exit(-1);
    }
    
    get_n_show_arp();
    exit(0);
    /*NOTREACHED*/
}
