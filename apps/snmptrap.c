/*
 * snmptrap.c - send snmp traps to a network entity.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/file.h>
#include <nlist.h>

#include "snmp.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

extern int  errno;
int	snmp_dump_packet = 0;

#define NUM_NETWORKS	16   /* max number of interfaces to check */

oid objid_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};
oid objid_sysdescr[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};

struct nlist nl[] = {
    { "_boottime" },
    { "" }
};


int snmp_input() {
}

#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 0
#endif
#define LOOPBACK    0x7f000001
u_long
get_myaddr() {
    int sd;
    struct ifconf ifc;
    struct ifreq conf[NUM_NETWORKS], *ifrp, ifreq;
    struct sockaddr_in *in_addr;
    int count;
    int interfaces;		/* number of interfaces returned by ioctl */

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	return 0;
    ifc.ifc_len = sizeof(conf);
    ifc.ifc_buf = (caddr_t)conf;
    if (ioctl(sd, SIOCGIFCONF, (char *)&ifc) < 0) {
	close(sd);
	return 0;
    }
    ifrp = ifc.ifc_req;
    interfaces = ifc.ifc_len / sizeof(struct ifreq);
    for(count = 0; count < interfaces; count++, ifrp++) {
	ifreq = *ifrp;
	if (ioctl(sd, SIOCGIFFLAGS, (char *)&ifreq) < 0)
	    continue;
	in_addr = (struct sockaddr_in *)&ifrp->ifr_addr;
	if ((ifreq.ifr_flags & IFF_UP)
	    && (ifreq.ifr_flags & IFF_RUNNING)
	    && !(ifreq.ifr_flags & IFF_LOOPBACK)
	    && in_addr->sin_addr.s_addr != LOOPBACK) {
		close(sd);
		return in_addr->sin_addr.s_addr;
	    }
    }
    close(sd);
    return 0;
}

/*
 * Returns uptime in centiseconds(!).
 */
long uptime() {
    struct timeval boottime, now, diff;
    mode_t kmem;

    if ((kmem = open("/dev/kmem", 0)) < 0)
	return 0;
/*    nlist("/vmunix", nl);*/
    nlist("/dev/ksyms", nl);
    if (nl[0].n_type == 0) {
	close(kmem);
	return 0;
    }
    
    lseek(kmem, (long)nl[0].n_value, L_SET);
    read(kmem, &boottime, sizeof(boottime));
    close(kmem);

    gettimeofday(&now, 0);
    now.tv_sec--;
    now.tv_usec += 1000000L;
    diff.tv_sec = now.tv_sec - boottime.tv_sec;
    diff.tv_usec = now.tv_usec - boottime.tv_usec;
    if (diff.tv_usec > 1000000L) {
	diff.tv_usec -= 1000000L;
	diff.tv_sec++;
    }
    return ((diff.tv_sec * 100) + (diff.tv_usec / 10000));
}

u_long parse_address(address)
    char *address;
{
    u_long addr;
    struct sockaddr_in saddr;
    struct hostent *hp;

    if ((addr = inet_addr(address)) != -1)
	return addr;
    hp = gethostbyname(address);
    if (hp == NULL) {
	fprintf(stderr, "unknown host: %s\n", address);
	return 0;
    } else {
	bcopy((char *)hp->h_addr, (char *)&saddr.sin_addr, hp->h_length);
	return saddr.sin_addr.s_addr;
    }

}
main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu;
    struct variable_list *vars;
    int	arg;
    char *gateway = NULL;
    char *community = NULL;
    char *trap = NULL, *specific = NULL, *agent = NULL;
    int dest_port = SNMP_TRAP_PORT;

    u_char  value[256];
    int	    name_length;	/* number of subid's in name */
    int	    got_enterprise = 0;
    int	    repeat_count = 1;
    struct variable_list    *vp;
    int     ret;

    init_mib();

    for(arg = 1; arg < argc; arg++)
    {
	if (argv[arg][0] == '-')
	{
	    switch(argv[arg][1])
	    {
	      case 'a':
		agent = argv[++arg];
		break;
	      case 'd':
		snmp_dump_packet++;
		break;
	      case 'r':
		if ((arg + 1) < argc)
		    repeat_count = atoi(argv[++arg]);
		else
		    goto usage;
		break;

	    case 'P':
		if (arg == argc - 1)
		{
		    printf("No value given to -P option\n");
		    exit(1);
		}
		dest_port = atoi(argv[++arg]);
		if (dest_port == 0)
		{
		    printf("Bad port number %s\n", argv[arg]);
		    exit(1);
		}
		break;

	      case 'e':
		got_enterprise = TRUE;
		arg++;
		name_length = MAX_NAME_LEN;
		if (!read_objid(argv[arg], value, &name_length))
		    goto usage;
		break;

	      default:
		printf("invalid option: -%c\n", argv[arg][1]);
		goto usage;
	    }
	    continue;
	}
	if (gateway == NULL)
	    gateway = argv[arg];
	else if (community == NULL)
	    community = argv[arg]; 
        else if (trap == NULL)
	    trap = argv[arg];
	else if (specific == NULL)
	    specific = argv[arg];
    }
    
    if (!(gateway && community && trap && specific))
	goto usage;

    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = gateway;
    session.community = (u_char *)community;
    session.community_len = strlen((char *)community);
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.authenticator = NULL;
    session.callback = snmp_input;
    session.callback_magic = NULL;
    session.remote_port = dest_port;
    ss = snmp_open(&session);
    if (ss == NULL) {
	printf("Couldn't open snmp\n");
	exit(-1);
    }

    pdu = snmp_pdu_create(TRP_REQ_MSG);
    if (got_enterprise)
    {
	pdu->enterprise = (oid *)malloc(name_length * sizeof(oid));
	bcopy((char *)value, (char *)pdu->enterprise,
	      name_length*sizeof(oid));
	pdu->enterprise_length = name_length;
    }
    else
    {
	pdu->enterprise = (oid *)malloc(sizeof(objid_enterprise));
	bcopy((char *)objid_enterprise, (char *)pdu->enterprise,
	      sizeof(objid_enterprise));
	pdu->enterprise_length = sizeof(objid_enterprise) / sizeof(oid);
    }
    if (agent != NULL)
	pdu->agent_addr.sin_addr.s_addr = parse_address(agent);
    else
	pdu->agent_addr.sin_addr.s_addr = get_myaddr();
    pdu->trap_type = atoi(trap);
    pdu->specific_type = atoi(specific);
    pdu->time = uptime();
    
    pdu->variables = vars = NULL;

    for(ret = 1; ret != 0;)
    {
	vp = (struct variable_list *)malloc(sizeof(struct variable_list));
	vp->next_variable = NULL;
	vp->name = NULL;
	vp->val.string = NULL;

	ret = input_variable(vp);
	if (ret == -1)
	    exit(1);

	if (ret == 1)
	{
	    /* add it to the list */
	    if (vars == NULL)
		/* if first variable */
		pdu->variables = vp;
	    else
		vars->next_variable = vp;

	    vars = vp;
	}
	else
	{
	    /* free the last (unused) variable */
	    if (vp->name)
		free((char *)vp->name);
	    if (vp->val.string)
		free((char *)vp->val.string);
	    free((char *)vp);
	}
    }

    for (; repeat_count > 0; repeat_count--)
    {
	if (snmp_send(ss, pdu)== 0)
	{
	    printf("error\n");
	    snmp_close(ss);
	    exit(1);
	}
	
	/*
	 * want to sleep if sending many traps
	 * give the destination a chance to read
	 */
	if ((repeat_count % 8) == 0)
	    sleep(1);	
    }
    snmp_close(ss);

    exit(0);

  usage:
    printf("usage: snmptrap host community trap-type specific-type \n\
\t[ -a agent-addr ] [-e enterprise-oid] [-d] [-r repeat-count#] [-P port#]\n");
    exit(1);
    /*NOTREACHED*/
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


int
input_variable(vp)
    struct variable_list    *vp;
{
    u_char  buf[256], value[256], ch;

    printf("Please enter the variable name: ");
    fflush(stdout);
    if (gets(buf) == NULL)
	exit(0);

    if (*buf == 0)
    {
	vp->name_length = 0;
	return 0;
    }

    vp->name_length = MAX_NAME_LEN;
    if (!read_objid(buf, value, &vp->name_length))
	return -1;
    vp->name = (oid *)malloc(vp->name_length * sizeof(oid));
    bcopy((char *)value, (char *)vp->name, vp->name_length * sizeof(oid));

    printf("Please enter variable type [i|s|x|d|n|o|t|a]: ");
    fflush(stdout);
    if (gets(buf) == NULL)
	exit(0);
    ch = *buf;
    switch(ch)
    {
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
    printf("Please enter the value: "); fflush(stdout);
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

    return 1;
}

