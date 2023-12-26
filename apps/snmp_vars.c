#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmp_vars.c,v 1.3 1996/11/14 15:16:09 tpt2 Exp $";
#endif

/*
 * snmp_vars.c - return a pointer to the named variable.
 *
 *
 */
/***********************************************************
	Copyright 1988, 1989, 1990 by Carnegie Mellon University
	Copyright 1989	TGV, Incorporated

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#define USE_NAME_AS_DESCRIPTION /*"se0" instead of text */
#define GATEWAY			/* MultiNet is always configured this way! */
#include <sys/types.h>
#include <sys/socket.h>
/* #include <sys/time.h> */
#include <sys/param.h>
/*#include <sys/dir.h>*?
#include <sys/user.h>
#include <sys/proc.h>
/*#include <machine/pte.h>*/
#include <sys/vm.h>
#include <netinet/in.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in_pcb.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#ifdef ULTRIX42
#include <xti.h>    /* needed for tcp_var.h to compile */
#endif /* ULTRIX42 */
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <nlist.h>
#include <sys/protosw.h>
#ifndef NULL
#define NULL 0
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "mib.h"
#include "snmp_vars.h"



#ifdef vax11c
#define ioctl socket_ioctl
#define perror socket_perror
#endif vax11c

extern char *Lookup_Device_Annotation();

static struct nlist nl[] = {
#define N_IPSTAT	0
	{ "_ipstat" },
#define N_IPFORWARDING	1
	{ "_ipforwarding" },
#define N_TCP_TTL	2
	{ "_tcp_ttl" },
#define N_UDPSTAT	3
	{ "_udpstat" },
#define N_IN_INTERFACES 4
	{ "_in_interfaces" },
#define N_ICMPSTAT	5
	{ "_icmpstat" },
#define N_IFNET		6
	{ "_ifnet" },
#define N_TCPSTAT	7
	{ "_tcpstat" },
#define N_TCB		8
	{ "_tcb" },
#define N_ARPTAB_SIZE	9
	{ "_arptab_size" },
#define N_ARPTAB       10
	{ "_arptab" },
#define N_IN_IFADDR    11
	{ "_in_ifaddr" },
#define N_BOOTTIME	12
	{ "_boottime" },
#ifdef ibm032
#define N_PROC		13
	{ "_proc" },
#define N_NPROC		14
	{ "_nproc" },
#define N_DMMIN		15
	{ "_dmmin" },
#define N_DMMAX		16
	{ "_dmmax" },
#define N_NSWAP		17
	{ "_nswap" },
#define N_USRPTMAP	18
	{ "_Usrptmap" },
#define N_USRPT		19
	{ "_usrpt" },
#endif
#ifdef ibm032
#define N_USERSIZE	20
	{ "_userSIZE" },
#endif
	0,
};

/*
 *	Each variable name is placed in the variable table, without the terminating
 * substring that determines the instance of the variable.  When a string is found that
 * is lexicographicly preceded by the input string, the function for that entry is
 * called to find the method of access of the instance of the named variable.  If
 * that variable is not found, NULL is returned, and the search through the table
 * continues (it should stop at the next entry).  If it is found, the function returns
 * a character pointer and a length or a function pointer.  The former is the address
 * of the operand, the latter is a write routine for the variable.
 *
 * u_char *
 * findVar(name, length, exact, var_len, write_method)
 * oid	    *name;	    IN/OUT - input name requested, output name found
 * int	    length;	    IN/OUT - number of sub-ids in the in and out oid's
 * int	    exact;	    IN - TRUE if an exact match was requested.
 * int	    len;	    OUT - length of variable or 0 if function returned.
 * int	    write_method;   OUT - 1 if function, 0 if char pointer.
 *
 * writeVar(doSet, var_val, var_val_type, var_val_len, statP)
 * int	    doSet;	    IN - 0 if only check of validity of operation
 * u_char   *var_val;	    IN - input or output buffer space
 * u_char   var_val_type;   IN - type of input buffer
 * int	    var_val_len;    IN - input and output buffer len
 * u_char   *statP;	    IN - pointer to local statistic
 */

long		long_return;
u_char		return_buf[256]; /* nee 64 */

init_snmp()
{
/*    nlist("/vmunix",nl);*/
  nlist("/dev/ksyms", nl);
  init_kmem("/dev/kmem");
  init_routes();

}

struct variable     variables[] = {
    /* these must be lexicographly ordered by the name field */
    {{MIB, 1, 1, 0},		9, STRING,  VERSION_DESCR, RWRITE, var_system },
    {{MIB, 1, 2, 0},		9, OBJID,   VERSION_ID, RONLY, var_system },
    {{MIB, 1, 3, 0},		9, TIMETICKS, UPTIME, RONLY, var_system },
    {{MIB, 2, 1, 0},		9, INTEGER, IFNUMBER, RONLY, var_system },
    {{MIB, 2, 2, 1, 1, 0xFF},  11, INTEGER, IFINDEX, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 2, 0xFF},  11, STRING,  IFDESCR, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 3, 0xFF},  11, INTEGER, IFTYPE, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 4, 0xFF},  11, INTEGER, IFMTU, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 5, 0xFF},  11, GAUGE,   IFSPEED, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 6, 0xFF},  11, STRING,  IFPHYSADDRESS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 7, 0xFF},  11, INTEGER, IFADMINSTATUS, RWRITE, var_ifEntry },
    {{MIB, 2, 2, 1, 8, 0xFF},  11, INTEGER, IFOPERSTATUS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 9, 0xFF},  11, TIMETICKS, IFLASTCHANGE, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 10, 0xFF}, 11, COUNTER, IFINOCTETS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 11, 0xFF}, 11, COUNTER, IFINUCASTPKTS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 12, 0xFF}, 11, COUNTER, IFINNUCASTPKTS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 13, 0xFF}, 11, COUNTER, IFINDISCARDS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 14, 0xFF}, 11, COUNTER, IFINERRORS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 15, 0xFF}, 11, COUNTER, IFINUNKNOWNPROTOS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 16, 0xFF}, 11, COUNTER, IFOUTOCTETS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 17, 0xFF}, 11, COUNTER, IFOUTUCASTPKTS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 18, 0xFF}, 11, COUNTER, IFOUTNUCASTPKTS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 19, 0xFF}, 11, COUNTER, IFOUTDISCARDS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 20, 0xFF}, 11, COUNTER, IFOUTERRORS, RONLY, var_ifEntry },
    {{MIB, 2, 2, 1, 21, 0xFF}, 11, GAUGE,   IFOUTQLEN, RONLY, var_ifEntry },
    {{MIB, 3, 1, 1, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 16, INTEGER,    ATIFINDEX, RONLY, var_atEntry },
    {{MIB, 3, 1, 1, 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 16, STRING,     ATPHYSADDRESS, RONLY, var_atEntry },
    {{MIB, 3, 1, 1, 3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 16, IPADDRESS,  ATNETADDRESS, RONLY, var_atEntry },
    {{MIB, 4, 1, 0},	    9, INTEGER, IPFORWARDING, RONLY, var_ip },
    {{MIB, 4, 2, 0},	    9, INTEGER, IPDEFAULTTTL, RONLY, var_ip },
    {{MIB, 4, 3, 0},	    9, COUNTER, IPINRECEIVES, RONLY, var_ip },
    {{MIB, 4, 4, 0},	    9, COUNTER, IPINHDRERRORS, RONLY, var_ip },
    {{MIB, 4, 5, 0},	    9, COUNTER, IPINADDRERRORS, RONLY, var_ip },
    {{MIB, 4, 6, 0},	    9, COUNTER, IPFORWDATAGRAMS, RONLY, var_ip },
    {{MIB, 4, 7, 0},	    9, COUNTER, IPINUNKNOWNPROTOS, RONLY, var_ip },
    {{MIB, 4, 8, 0},	    9, COUNTER, IPINDISCARDS, RONLY, var_ip },
    {{MIB, 4, 9, 0},	    9, COUNTER, IPINDELIVERS, RONLY, var_ip },
    {{MIB, 4, 10, 0},	    9, COUNTER, IPOUTREQUESTS, RONLY, var_ip },
    {{MIB, 4, 11, 0},	    9, COUNTER, IPOUTDISCARDS, RONLY, var_ip },
    {{MIB, 4, 12, 0},	    9, COUNTER, IPOUTNOROUTES, RONLY, var_ip },
    {{MIB, 4, 13, 0},	    9, INTEGER, IPREASMTIMEOUT, RONLY, var_ip },
    {{MIB, 4, 14, 0},	    9, COUNTER, IPREASMREQDS, RONLY, var_ip },
    {{MIB, 4, 15, 0},	    9, COUNTER, IPREASMOKS, RONLY, var_ip },
    {{MIB, 4, 16, 0},	    9, COUNTER, IPREASMFAILS, RONLY, var_ip },
    {{MIB, 4, 17, 0},	    9, COUNTER, IPFRAGOKS, RONLY, var_ip },
    {{MIB, 4, 18, 0},	    9, COUNTER, IPFRAGFAILS, RONLY, var_ip },
    {{MIB, 4, 19, 0},	    9, COUNTER, IPFRAGCREATES, RONLY, var_ip },
    {{MIB, 4, 20, 1, 1, 0xFF, 0xFF, 0xFF, 0xFF}, 14, IPADDRESS, IPADADDR, RONLY, var_ipAddrEntry },
    {{MIB, 4, 20, 1, 2, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPADIFINDEX, RONLY, var_ipAddrEntry },
    {{MIB, 4, 20, 1, 3, 0xFF, 0xFF, 0xFF, 0xFF}, 14, IPADDRESS, IPADNETMASK, RONLY, var_ipAddrEntry },
    {{MIB, 4, 20, 1, 4, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPADBCASTADDR, RONLY, var_ipAddrEntry },
    {{MIB, 4, 21, 1, 1, 0xFF, 0xFF, 0xFF, 0xFF}, 14, IPADDRESS, IPROUTEDEST, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 2, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPROUTEIFINDEX, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 3, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPROUTEMETRIC1, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 4, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPROUTEMETRIC2, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 5, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPROUTEMETRIC3, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 6, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPROUTEMETRIC4, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 7, 0xFF, 0xFF, 0xFF, 0xFF}, 14, IPADDRESS, IPROUTENEXTHOP, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 8, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPROUTETYPE, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 9, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPROUTEPROTO, RONLY, var_ipRouteEntry },
    {{MIB, 4, 21, 1, 10, 0xFF, 0xFF, 0xFF, 0xFF}, 14, INTEGER,	IPROUTEAGE, RONLY, var_ipRouteEntry },
    {{MIB, 5, 1, 0},	    9, COUNTER, ICMPINMSGS, RONLY, var_icmp },
    {{MIB, 5, 2, 0},	    9, COUNTER, ICMPINERRORS, RONLY, var_icmp },
    {{MIB, 5, 3, 0},	    9, COUNTER, ICMPINDESTUNREACHS, RONLY, var_icmp },
    {{MIB, 5, 4, 0},	    9, COUNTER, ICMPINTIMEEXCDS, RONLY, var_icmp },
    {{MIB, 5, 5, 0},	    9, COUNTER, ICMPINPARMPROBS, RONLY, var_icmp },
    {{MIB, 5, 6, 0},	    9, COUNTER, ICMPINSRCQUENCHS, RONLY, var_icmp },
    {{MIB, 5, 7, 0},	    9, COUNTER, ICMPINREDIRECTS, RONLY, var_icmp },
    {{MIB, 5, 8, 0},	    9, COUNTER, ICMPINECHOS, RONLY, var_icmp },
    {{MIB, 5, 9, 0},	    9, COUNTER, ICMPINECHOREPS, RONLY, var_icmp },
    {{MIB, 5, 10, 0},	    9, COUNTER, ICMPINTIMESTAMPS, RONLY, var_icmp },
    {{MIB, 5, 11, 0},	    9, COUNTER, ICMPINTIMESTAMPREPS, RONLY, var_icmp },
    {{MIB, 5, 12, 0},	    9, COUNTER, ICMPINADDRMASKS, RONLY, var_icmp },
    {{MIB, 5, 13, 0},	    9, COUNTER, ICMPINADDRMASKREPS, RONLY, var_icmp },
    {{MIB, 5, 14, 0},	    9, COUNTER, ICMPOUTMSGS, RONLY, var_icmp },
    {{MIB, 5, 15, 0},	    9, COUNTER, ICMPOUTERRORS, RONLY, var_icmp },
    {{MIB, 5, 16, 0},	    9, COUNTER, ICMPOUTDESTUNREACHS, RONLY, var_icmp },
    {{MIB, 5, 17, 0},	    9, COUNTER, ICMPOUTTIMEEXCDS, RONLY, var_icmp },
    {{MIB, 5, 18, 0},	    9, COUNTER, ICMPOUTPARMPROBS, RONLY, var_icmp },
    {{MIB, 5, 19, 0},	    9, COUNTER, ICMPOUTSRCQUENCHS, RONLY, var_icmp },
    {{MIB, 5, 20, 0},	    9, COUNTER, ICMPOUTREDIRECTS, RONLY, var_icmp },
    {{MIB, 5, 21, 0},	    9, COUNTER, ICMPOUTECHOS, RONLY, var_icmp },
    {{MIB, 5, 22, 0},	    9, COUNTER, ICMPOUTECHOREPS, RONLY, var_icmp },
    {{MIB, 5, 23, 0},	    9, COUNTER, ICMPOUTTIMESTAMPS, RONLY, var_icmp },
    {{MIB, 5, 24, 0},	    9, COUNTER, ICMPOUTTIMESTAMPREPS, RONLY, var_icmp },
    {{MIB, 5, 25, 0},	    9, COUNTER, ICMPOUTADDRMASKS, RONLY, var_icmp },
    {{MIB, 5, 26, 0},	    9, COUNTER, ICMPOUTADDRMASKREPS, RONLY, var_icmp },
    {{MIB, 6, 1, 0},	    9, INTEGER, TCPRTOALGORITHM, RONLY, var_tcp },
    {{MIB, 6, 2, 0},	    9, INTEGER, TCPRTOMIN, RONLY, var_tcp },
    {{MIB, 6, 3, 0},	    9, INTEGER, TCPRTOMAX, RONLY, var_tcp },
    {{MIB, 6, 4, 0},	    9, INTEGER, TCPMAXCONN, RONLY, var_tcp },
    {{MIB, 6, 5, 0},	    9, COUNTER, TCPACTIVEOPENS, RONLY, var_tcp },
    {{MIB, 6, 6, 0},	    9, COUNTER, TCPPASSIVEOPENS, RONLY, var_tcp },
    {{MIB, 6, 7, 0},	    9, COUNTER, TCPATTEMPTFAILS, RONLY, var_tcp },
    {{MIB, 6, 8, 0},	    9, COUNTER, TCPESTABRESETS, RONLY, var_tcp },
    {{MIB, 6, 9, 0},	    9, GAUGE,	TCPCURRESTAB, RONLY, var_tcp },
    {{MIB, 6,10, 0},	    9, COUNTER, TCPINSEGS, RONLY, var_tcp },
    {{MIB, 6,11, 0},	    9, COUNTER, TCPOUTSEGS, RONLY, var_tcp },
    {{MIB, 6,12, 0},	    9, COUNTER, TCPRETRANSSEGS, RONLY, var_tcp },
    {{MIB, 6,13, 1, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  20, INTEGER, TCPCONNSTATE, RONLY, var_tcp },
    {{MIB, 6,13, 1, 2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  20, IPADDRESS, TCPCONNLOCALADDRESS, RONLY, var_tcp },
    {{MIB, 6,13, 1, 3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  20, INTEGER, TCPCONNLOCALPORT, RONLY, var_tcp },
    {{MIB, 6,13, 1, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  20, IPADDRESS, TCPCONNREMADDRESS, RONLY, var_tcp },
    {{MIB, 6,13, 1, 5, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},  20, INTEGER, TCPCONNREMPORT, RONLY, var_tcp },
    {{MIB, 7, 1, 0},	    9, COUNTER, UDPINDATAGRAMS, RONLY, var_udp },
    {{MIB, 7, 2, 0},	    9, COUNTER, UDPNOPORTS, RONLY, var_udp },
    {{MIB, 7, 3, 0},	    9, COUNTER, UDPINERRORS, RONLY, var_udp },
    {{MIB, 7, 4, 0},	    9, COUNTER, UDPOUTDATAGRAMS, RONLY, var_udp }
};




/*
 * getStatPtr - return a pointer to the named variable, as well as it's
 * type, length, and access control list.
 *
 * If an exact match for the variable name exists, it is returned.  If not,
 * and exact is false, the next variable lexicographically after the
 * requested one is returned.
 *
 * If no appropriate variable can be found, NULL is returned.
 */
u_char	*
getStatPtr(name, namelen, type, len, acl, exact, access_method)
    oid		*name;	    /* IN - name of var, OUT - name matched */
    int		*namelen;   /* IN -number of sub-ids in name, OUT - subid-is in matched name */
    u_char	*type;	    /* OUT - type of matched variable */
    int		*len;	    /* OUT - length of matched variable */
    u_short	*acl;	    /* OUT - access control list */
    int		exact;	    /* IN - TRUE if exact match wanted */
    int		*access_method; /* OUT - 1 if function, 0 if char * */
{

    register struct variable	*vp;

    register int	x;
    register u_char	*access;
    int			result;
    register int	minlen;
    register oid	*name1, *name2;

    for(x = 0, vp = variables; x < sizeof(variables)/sizeof(struct variable); vp++, x++){
	if (*namelen < (int)vp->namelen)
	    minlen = *namelen;
	else
	    minlen = (int)vp->namelen;
	name1 = name; name2 = vp->name;
	result = 0;
	while(minlen-- > 0){
	    if (*name1 < *name2){
		result = -1;
		break;
	    }
	    if (*name2++ < *name1++){
		result = 1;
		break;
	    }
	}
	if (result == 0){
	    if (*namelen < (int)vp->namelen)
		result = -1;	/* name1 shorter so it is "less" */
	    else if ((int)vp->namelen < *namelen)
		result = 1;
	    else
		result = 0;
	}
/*	result = compare(name, *namelen, vp->name, (int)vp->namelen); */
	if ((result < 0) || (exact && (result == 0))){
	    access = (*(vp->findVar))(vp, name, namelen, exact, len, access_method);
	    if (access != NULL)
		break;
	}
    }
    if (x == sizeof(variables)/sizeof(struct variable))
	return NULL;

    /* vp now points to the approprate struct */
    *type = vp->type;
    *acl = vp->acl;
    return access;
}



int
compare(name1, len1, name2, len2)
    register oid	    *name1, *name2;
    register int	    len1, len2;
{
    register int    len;

    /* len = minimum of len1 and len2 */
    if (len1 < len2)
	len = len1;
    else
	len = len2;
    /* find first non-matching byte */
    while(len-- > 0){
	if (*name1 < *name2)
	    return -1;
	if (*name2++ < *name1++)
	    return 1;
    }
    /* bytes match up to length of shorter string */
    if (len1 < len2)
	return -1;  /* name1 shorter, so it is "less" */
    if (len2 < len1)
	return 1;
    return 0;	/* both strings are equal */
}

char version_descr[32] = "Unix 4.3BSD";
oid version_id[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};

u_char *
var_system(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - 1 if function, 0 if char pointer. */
{
    struct timeval now, boottime;
    extern int writeVersion();

    if (exact && (compare(name, *length, vp->name, (int)vp->namelen) != 0))
	return NULL;
    bcopy((char *)vp->name, (char *)name, (int)vp->namelen * sizeof(oid));
    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    switch (vp->magic){
	case VERSION_DESCR:
	    *var_len = strlen(version_descr);
	    *write_method = writeVersion;
	    return (u_char *)version_descr;
	case VERSION_ID:
	    *var_len = sizeof(version_id);
	    return (u_char *)version_id;
	case UPTIME:
	    klseek(nl[N_BOOTTIME].n_value);
	    klread((char *)&boottime, sizeof(boottime));
	    gettimeofday(&now, (struct timezone *)0);
	    long_return = (now.tv_sec - boottime.tv_sec) * 100
		    + (now.tv_usec - boottime.tv_usec) / 10000;
	    return (u_char *) &long_return;
	case IFNUMBER:
	    long_return = Interface_Scan_Get_Count();
	    return (u_char *) &long_return;
	default:
	    ERROR("");
    }
    return NULL;
}

#include <ctype.h>
int
writeVersion(doSet, var_val, var_val_type, var_val_len, statP)
   int      doSet;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
{
    int bigsize = 1000;
    u_char buf[sizeof(version_descr)], *cp;
    int count, size;

    if (var_val_type != STRING){
	printf("not string\n");
	return FALSE;
    }
    if (var_val_len > sizeof(version_descr)-1){
	printf("bad length\n");
	return FALSE;
    }
    size = sizeof(buf);
    asn_parse_string(var_val, &bigsize, &var_val_type, (long *)buf, &size);
    for(cp = buf, count = 0; count < size; count++, cp++){
	if (!isprint(*cp)){
	    printf("not print %x\n", *cp);
	    return FALSE;
	}
    }
    buf[size] = 0;
    if (doSet){
	strcpy(version_descr, buf);
	
    }
    return TRUE;
}



u_char *
var_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - 1 if function, 0 if char pointer. */
{
    oid			newname[MAX_NAME_LEN];
    register int	interface;
    int result, count;
    static struct ifnet ifnet;
    static struct in_ifaddr in_ifaddr;
    static char Name[16];
    register char *cp;

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    /* find "next" interface */
    count = Interface_Scan_Get_Count();
    for(interface = 1; interface <= count; interface++){
	newname[10] = (oid)interface;
	result = compare(name, *length, newname, (int)vp->namelen);
	if ((exact && (result == 0)) || (!exact && (result < 0)))
	    break;
    }
    if (interface > count)
	return NULL;

    bcopy((char *)newname, (char *)name, (int)vp->namelen * sizeof(oid));
    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);

    Interface_Scan_By_Index(interface, Name, &ifnet, &in_ifaddr);
    switch (vp->magic){
	case IFINDEX:
	    long_return = interface;
	    return (u_char *) &long_return;
	case IFDESCR:
#define USE_NAME_AS_DESCRIPTION
#ifdef USE_NAME_AS_DESCRIPTION
	    cp = Name;
#else  USE_NAME_AS_DESCRIPTION
	    cp = Lookup_Device_Annotation(Name, "snmp-descr");
	    if (!cp)
		cp = Lookup_Device_Annotation(Name, 0);
	    if (!cp) cp = Name;
#endif USE_NAME_AS_DESCRIPTION
	    *var_len = strlen(cp);
	    return (u_char *)cp;
	case IFTYPE:
#if 0
	    cp = Lookup_Device_Annotation(Name, "snmp-type");
	    if (cp) long_return = atoi(cp);
	    else
#endif
		long_return = 1;	/* OTHER */
	    return (u_char *) &long_return;
	case IFMTU: {
	    long_return = (long) ifnet.if_mtu;
	    return (u_char *) &long_return;
	}
	case IFSPEED:
#if 0
	    cp = Lookup_Device_Annotation(Name, "snmp-speed");
	    if (cp) long_return = atoi(cp);
	    else
#endif
	    long_return = 1;	/* OTHER */
	    return (u_char *) &long_return;
	case IFPHYSADDRESS:
#if 0
	    if (Lookup_Device_Annotation(Name, "ethernet-device")) {
		Interface_Get_Ether_By_Index(interface, return_buf);
		*var_len = 6;
		return(u_char *) return_buf;
	    } else {
		long_return = 0;
		return (u_char *) long_return;
	    }
#endif
		*var_len = 6;
		return (u_char *)return_buf;
	case IFADMINSTATUS:
	    long_return = ifnet.if_flags & IFF_RUNNING ? 1 : 2;
	    return (u_char *) &long_return;
	case IFOPERSTATUS:
	    long_return = ifnet.if_flags & IFF_UP ? 1 : 2;
	    return (u_char *) &long_return;
	case IFLASTCHANGE:
	    long_return = 0; /* XXX */
	    return (u_char *) &long_return;
	case IFINOCTETS:
	    long_return = ifnet.if_ipackets * (ifnet.if_mtu / 2); /* XXX */
	    return (u_char *) &long_return;
	case IFINUCASTPKTS:
	    long_return = ifnet.if_ipackets;
	    return (u_char *) &long_return;
	case IFINNUCASTPKTS:
	    long_return = 0; /* XXX */
	    return (u_char *) &long_return;
	case IFINDISCARDS:
	    long_return = 0; /* XXX */
	    return (u_char *) &long_return;
	case IFINERRORS:
	    return (u_char *) &ifnet.if_ierrors;
	case IFINUNKNOWNPROTOS:
	    long_return = 0; /* XXX */
	    return (u_char *) &long_return;
	case IFOUTOCTETS:
	    long_return = ifnet.if_opackets * (ifnet.if_mtu / 2); /* XXX */
	    return (u_char *) &long_return;
	case IFOUTUCASTPKTS:
	    long_return = ifnet.if_opackets;
	    return (u_char *) &long_return;
	case IFOUTNUCASTPKTS:
	    long_return = 0; /* XXX */
	    return (u_char *) &long_return;
	case IFOUTDISCARDS:
	    return (u_char *) &ifnet.if_snd.ifq_drops;
	case IFOUTERRORS:
	    return (u_char *) &ifnet.if_oerrors;
	case IFOUTQLEN:
	    return (u_char *) &ifnet.if_snd.ifq_len;
	default:
	    ERROR("");
    }
    return NULL;
}

/*
 * Read the ARP table
 */

u_char *
var_atEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;	/* IN - pointer to variable entry that points here */
    register oid	    *name;	/* IN/OUT - input name requested, output name found */
    register int	    *length;	/* IN/OUT - length of input and output oid's */
    int			    exact;	/* IN - TRUE if an exact match was requested. */
    int			    *var_len;	/* OUT - length of variable or 0 if function returned. */
    int			    (**write_method)(); /* OUT - 1 if function, 0 if char pointer. */
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.3.1.1.1.interface.1.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 12.
     */
    u_char		    *cp;
    oid			    *op;
    oid			    lowest[16];
    oid			    current[16];
    static char		    PhysAddr[6], LowPhysAddr[6];
    u_long		    Addr, LowAddr;

    /* fill in object part of name for current (less sizeof instance part) */

    bcopy((char *)vp->name, (char *)current, (int)(vp->namelen - 6) * sizeof(oid));

    LowAddr = -1;      /* Don't have one yet */
    ARP_Scan_Init();
    for (;;) {
	if (ARP_Scan_Next(&Addr, PhysAddr) == 0) break;
	current[10] = 1;	/* IfIndex == 1 (ethernet???) XXX */
	current[11] = 1;
	cp = (u_char *)&Addr;
	op = current + 12;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;

	if (exact){
	    if (compare(current, 16, name, *length) == 0){
		bcopy((char *)current, (char *)lowest, 16 * sizeof(oid));
		LowAddr = Addr;
		bcopy(PhysAddr, LowPhysAddr, sizeof(PhysAddr));
		break;	/* no need to search further */
	    }
	} else {
	    if ((compare(current, 16, name, *length) > 0) &&
		 ((LowAddr == -1) || (compare(current, 16, lowest, 16) < 0))){
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, save this one as the "next" one.
		 */
		bcopy((char *)current, (char *)lowest, 16 * sizeof(oid));
		LowAddr = Addr;
		bcopy(PhysAddr, LowPhysAddr, sizeof(PhysAddr));
	    }
	}
    }
    if (LowAddr == -1) return(NULL);

    bcopy((char *)lowest, (char *)name, 16 * sizeof(oid));
    *length = 16;
    *write_method = 0;
    switch(vp->magic){
	case ATIFINDEX:
	    *var_len = sizeof long_return;
	    long_return = 1; /* XXX */
	    return (u_char *)&long_return;
	case ATPHYSADDRESS:
	    *var_len = sizeof(LowPhysAddr);
	    return (u_char *)LowPhysAddr;
	case ATNETADDRESS:
	    *var_len = sizeof long_return;
	    long_return = LowAddr;
	    return (u_char *)&long_return;
	default:
	    ERROR("");
   }
   return NULL;
}

u_char *
var_ip(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - 1 if function, 0 if char pointer. */
{
    int i;
    static struct ipstat ipstat;

    if (exact && (compare(name, *length, vp->name, (int)vp->namelen) != 0))
	return NULL;
    bcopy((char *)vp->name, (char *)name, (int)vp->namelen * sizeof(oid));

    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    /*
     *	Get the IP statistics from the kernel...
     */

    klseek(nl[N_IPSTAT].n_value);
    klread((char *)&ipstat, sizeof (ipstat));

    switch (vp->magic){
	case IPFORWARDING:
	    klseek(nl[N_IPFORWARDING].n_value);
	    klread((char *) &i, sizeof(i));
	    if (i) {
		klseek(nl[N_IN_INTERFACES].n_value);
		klread((char *) &i, sizeof(i));
		if (i > 1)
		    long_return = 1;		/* GATEWAY */
		else
		    long_return = 2;		/* GATEWAY configured as HOST */
	    } else {
		long_return = 2;	    /* HOST    */
	    }
	    return (u_char *) &long_return;
	case IPDEFAULTTTL:
	    /*
	     *	Allow for a kernel w/o TCP.
	     */
	    if (nl[N_TCP_TTL].n_value) {
		klseek(nl[N_TCP_TTL].n_value);
		klread((char *) &long_return, sizeof(long_return));
	    } else long_return = 60;	    /* XXX */
	    return (u_char *) &long_return;
	case IPINRECEIVES:
	    return (u_char *) &ipstat.ips_total;
	case IPINHDRERRORS:
	    long_return = ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen;
	    return (u_char *) &long_return;
	case IPINADDRERRORS:
	    return (u_char *) &ipstat.ips_cantforward;
	case IPFORWDATAGRAMS:
	    return (u_char *) &ipstat.ips_forward;
	case IPINUNKNOWNPROTOS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPINDISCARDS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPINDELIVERS:
	    long_return = ipstat.ips_total -
			 (ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen);
	    return (u_char *) &long_return;
	case IPOUTREQUESTS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPOUTDISCARDS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPOUTNOROUTES:
	    return (u_char *) &ipstat.ips_cantforward;
	case IPREASMTIMEOUT:
	    long_return = IPFRAGTTL;
	    return (u_char *) &long_return;
	case IPREASMREQDS:
	    return (u_char *) &ipstat.ips_fragments;
	case IPREASMOKS:
	    return (u_char *) &ipstat.ips_fragments;
	case IPREASMFAILS:
	    long_return = ipstat.ips_fragdropped + ipstat.ips_fragtimeout;
	    return (u_char *) &long_return;
	case IPFRAGOKS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPFRAGFAILS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPFRAGCREATES:
	    long_return = 0;
	    return (u_char *) &long_return;
	default:
	    ERROR("");
    }
    return NULL;
}

u_char *
var_ipAddrEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - 1 if function, 0 if char pointer. */
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.20.1.?.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
    oid			    lowest[14];
    oid			    current[14], *op;
    u_char		    *cp;
    int			    interface, lowinterface=0;
    static struct ifnet ifnet;
    static struct in_ifaddr in_ifaddr, lowin_ifaddr;

    /* fill in object part of name for current (less sizeof instance part) */

    bcopy((char *)vp->name, (char *)current, (int)(vp->namelen - 4) * sizeof(oid));

    Interface_Scan_Init();
    for (;;) {
	if (Interface_Scan_Next(&interface, (char *)0, &ifnet, &in_ifaddr) == 0) break;

	cp = (u_char *)&(((struct sockaddr_in *) &(in_ifaddr.ia_addr))->sin_addr.s_addr);
	op = current + 10;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;

	if (exact){
	    if (compare(current, 14, name, *length) == 0){
		bcopy((char *)current, (char *)lowest, 14 * sizeof(oid));
		lowinterface = interface;
		lowin_ifaddr = in_ifaddr;
		break;	/* no need to search further */
	    }
	} else {
	    if ((compare(current, 14, name, *length) > 0) &&
		 (!lowinterface || (compare(current, 14, lowest, 14) < 0))){
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, save this one as the "next" one.
		 */
		lowinterface = interface;
		lowin_ifaddr = in_ifaddr;
		bcopy((char *)current, (char *)lowest, 14 * sizeof(oid));
	    }
	}
    }
    if (!lowinterface) return(NULL);
    bcopy((char *)lowest, (char *)name, 14 * sizeof(oid));
    *length = 14;
    *write_method = 0;
    *var_len = sizeof(long_return);
    switch(vp->magic){
	case IPADADDR:
	    return(u_char *) &((struct sockaddr_in *) &lowin_ifaddr.ia_addr)->sin_addr.s_addr;
	case IPADIFINDEX:
	    long_return = lowinterface;
	    return(u_char *) &long_return;
	case IPADNETMASK:
	    long_return = ntohl(lowin_ifaddr.ia_subnetmask);
	    return(u_char *) &long_return;
	case IPADBCASTADDR:
	    long_return = ntohl(((struct sockaddr_in *) &lowin_ifaddr.ia_addr)->sin_addr.s_addr) & 1;
	    return(u_char *) &long_return;
	default:
	    ERROR("");
    }
    return NULL;
}


u_char *
var_icmp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - 1 if function, 0 if char pointer. */
{
    register int i;
    static struct icmpstat icmpstat;

    if (exact && (compare(name, *length, vp->name, (int)vp->namelen) != 0))
	return NULL;
    bcopy((char *)vp->name, (char *)name, (int)vp->namelen * sizeof(oid));
    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long); /* all following variables are sizeof long */

    /*
     *	Get the UDP statistics from the kernel...
     */

    klseek(nl[N_ICMPSTAT].n_value);
    klread((char *)&icmpstat, sizeof (icmpstat));

    switch (vp->magic){
	case ICMPINMSGS:
	    long_return = icmpstat.icps_badcode + icmpstat.icps_tooshort +
			  icmpstat.icps_checksum + icmpstat.icps_badlen;
	    for (i=0; i <= ICMP_MAXTYPE; i++)
		long_return += icmpstat.icps_inhist[i];
	    return (u_char *)&long_return;
	case ICMPINERRORS:
	    long_return = icmpstat.icps_badcode + icmpstat.icps_tooshort +
			  icmpstat.icps_checksum + icmpstat.icps_badlen;
	    return (u_char *)&long_return;
	case ICMPINDESTUNREACHS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_UNREACH];
	case ICMPINTIMEEXCDS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_TIMXCEED];
	case ICMPINPARMPROBS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_PARAMPROB];
	case ICMPINSRCQUENCHS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_SOURCEQUENCH];
	case ICMPINREDIRECTS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_REDIRECT];
	case ICMPINECHOS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_ECHO];
	case ICMPINECHOREPS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_ECHOREPLY];
	case ICMPINTIMESTAMPS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_TSTAMP];
	case ICMPINTIMESTAMPREPS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_TSTAMPREPLY];
	case ICMPINADDRMASKS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_MASKREQ];
	case ICMPINADDRMASKREPS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_MASKREPLY];
	case ICMPOUTMSGS:
	    long_return = icmpstat.icps_oldshort + icmpstat.icps_oldicmp;
	    for (i=0; i <= ICMP_MAXTYPE; i++)
		long_return += icmpstat.icps_outhist[i];
	    return (u_char *)&long_return;
	case ICMPOUTERRORS:
	    long_return = icmpstat.icps_oldshort + icmpstat.icps_oldicmp;
	    return (u_char *)&long_return;
	case ICMPOUTDESTUNREACHS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_UNREACH];
	case ICMPOUTTIMEEXCDS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_TIMXCEED];
	case ICMPOUTPARMPROBS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_PARAMPROB];
	case ICMPOUTSRCQUENCHS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_SOURCEQUENCH];
	case ICMPOUTREDIRECTS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_REDIRECT];
	case ICMPOUTECHOS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_ECHO];
	case ICMPOUTECHOREPS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_ECHOREPLY];
	case ICMPOUTTIMESTAMPS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_TSTAMP];
	case ICMPOUTTIMESTAMPREPS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_TSTAMPREPLY];
	case ICMPOUTADDRMASKS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_MASKREQ];
	case ICMPOUTADDRMASKREPS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_MASKREPLY];
	default:
	    ERROR("");
    }
    return NULL;
}


u_char *
var_udp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - 1 if function, 0 if char pointer. */
{
    static struct udpstat udpstat;

    if (exact && (compare(name, *length, vp->name, (int)vp->namelen) != 0))
	return NULL;
    bcopy((char *)vp->name, (char *)name, (int)vp->namelen * sizeof(oid));

    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    /*
     *	Get the IP statistics from the kernel...
     */

    klseek(nl[N_UDPSTAT].n_value);
    klread((char *)&udpstat, sizeof (udpstat));

    switch (vp->magic){
	case UDPINDATAGRAMS:
	case UDPNOPORTS:
	case UDPOUTDATAGRAMS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case UDPINERRORS:
	    long_return = udpstat.udps_hdrops + udpstat.udps_badsum +
			  udpstat.udps_badlen;
	    return (u_char *) &long_return;
	default:
	    ERROR("");
    }
    return NULL;
}

u_char *
var_tcp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - 1 if function, 0 if char pointer. */
{
    int i;
    static struct tcpstat tcpstat;
    oid newname[MAX_NAME_LEN], lowest[MAX_NAME_LEN], *op;
    u_char *cp;
    int State, LowState;
    static struct inpcb inpcb, Lowinpcb;

    /*
     *	Allow for a kernel w/o TCP
     */

    if (nl[N_TCPSTAT].n_value == 0) return(NULL);

    if (vp->magic < TCPCONNSTATE) {
	if (exact && (compare(name, *length, vp->name, (int)vp->namelen) != 0))
	    return NULL;
	bcopy((char *)vp->name, (char *)name, (int)vp->namelen * sizeof(oid));

	*length = vp->namelen;
	*write_method = 0;
	*var_len = sizeof(long);    /* default length */
	/*
	 *  Get the TCP statistics from the kernel...
	 */

	klseek(nl[N_TCPSTAT].n_value);
	klread((char *)&tcpstat, sizeof (tcpstat));

	switch (vp->magic){
	    case TCPRTOALGORITHM:
		long_return = 4;	/* Van Jacobsen's algorithm */	/* XXX */
		return (u_char *) &long_return;
	    case TCPRTOMIN:
		long_return = TCPTV_MIN / PR_SLOWHZ * 1000;
		return (u_char *) &long_return;
	    case TCPRTOMAX:
		long_return = TCPTV_REXMTMAX / PR_SLOWHZ * 1000;
		return (u_char *) &long_return;
	    case TCPMAXCONN:
		long_return = -1;
		return (u_char *) &long_return;
	    case TCPACTIVEOPENS:
		return (u_char *) &tcpstat.tcps_connattempt;
	    case TCPPASSIVEOPENS:
		return (u_char *) &tcpstat.tcps_accepts;
	    case TCPATTEMPTFAILS:
		return (u_char *) &tcpstat.tcps_conndrops;
	    case TCPESTABRESETS:
		return (u_char *) &tcpstat.tcps_drops;
	    case TCPCURRESTAB:
		long_return = TCP_Count_Connections();
		return (u_char *) &long_return;
	    case TCPINSEGS:
		return (u_char *) &tcpstat.tcps_rcvtotal;
	    case TCPOUTSEGS:
		return (u_char *) &tcpstat.tcps_sndtotal;
	    case TCPRETRANSSEGS:
		return (u_char *) &tcpstat.tcps_sndrexmitpack;
	    default:
		ERROR("");
	}
    } else {	/* Info about a particular connection */
	bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
	/* find "next" connection */
Again:
LowState = -1;	    /* Don't have one yet */
	TCP_Scan_Init();
	for (;;) {
	    if ((i = TCP_Scan_Next(&State, &inpcb)) < 0) goto Again;
	    if (i == 0) break;	    /* Done */
	    cp = (u_char *)&inpcb.inp_laddr.s_addr;
	    op = newname + 10;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[14] = ntohs(inpcb.inp_lport);

	    cp = (u_char *)&inpcb.inp_faddr.s_addr;
	    op = newname + 15;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[19] = ntohs(inpcb.inp_fport);

	    if (exact){
		if (compare(newname, 20, name, *length) == 0){
		    bcopy((char *)newname, (char *)lowest, 20 * sizeof(oid));
		    LowState = State;
		    Lowinpcb = inpcb;
		    break;  /* no need to search further */
		}
	    } else {
		if ((compare(newname, 20, name, *length) > 0) &&
		     ((LowState < 0) || (compare(newname, 20, lowest, 20) < 0))){
		    /*
		     * if new one is greater than input and closer to input than
		     * previous lowest, save this one as the "next" one.
		     */
		    bcopy((char *)newname, (char *)lowest, 20 * sizeof(oid));
		    LowState = State;
		    Lowinpcb = inpcb;
		}
	    }
	}
	if (LowState < 0) return(NULL);
	bcopy((char *)lowest, (char *)name, (int)vp->namelen * sizeof(oid));
	*length = vp->namelen;
	*write_method = 0;
	*var_len = sizeof(long);
	switch (vp->magic) {
	    case TCPCONNSTATE: {
		static int StateMap[]={1, 2, 3, 4, 5, 8, 6, 10, 9, 7, 11};
		return (u_char *) &StateMap[LowState];
	    }
	    case TCPCONNLOCALADDRESS:
		return (u_char *) &Lowinpcb.inp_laddr.s_addr;
	    case TCPCONNLOCALPORT:
		long_return = ntohs(Lowinpcb.inp_lport);
		return (u_char *) &long_return;
	    case TCPCONNREMADDRESS:
		return (u_char *) &Lowinpcb.inp_faddr.s_addr;
	    case TCPCONNREMPORT:
		long_return = ntohs(Lowinpcb.inp_fport);
		return (u_char *) &long_return;
	}
    }
    return NULL;
}

/*
 *	Print INTERNET connections
 */

static int TCP_Count_Connections()
{
	int Established;
	struct inpcb cb;
	register struct inpcb *prev, *next;
	struct inpcb inpcb;
	struct tcpcb tcpcb;

Again:	/*
	 *	Prepare to scan the control blocks
	 */
	Established = 0;
	klseek(nl[N_TCB].n_value);
	klread((char *)&cb, sizeof(struct inpcb));
	inpcb = cb;
	prev = (struct inpcb *) nl[N_TCB].n_value;
	/*
	 *	Scan the control blocks
	 */
	while (inpcb.inp_next != (struct inpcb *) nl[N_TCB].n_value) {
		next = inpcb.inp_next;
		klseek((caddr_t)next);
		klread((char *)&inpcb, sizeof (inpcb));
		if (inpcb.inp_prev != prev) {	    /* ??? */
			sleep(1);
			goto Again;
		}
		if (inet_lnaof(inpcb.inp_laddr) == INADDR_ANY) {
			prev = next;
			continue;
		}
		klseek((caddr_t)inpcb.inp_ppcb);
		klread((char *)&tcpcb, sizeof (tcpcb));
		if ((tcpcb.t_state == TCPS_ESTABLISHED) ||
		    (tcpcb.t_state == TCPS_CLOSE_WAIT))
		    Established++;
		prev = next;
	}
	return(Established);
}


static struct inpcb inpcb, *prev;

static TCP_Scan_Init()
{
	klseek(nl[N_TCB].n_value);
	klread((char *)&inpcb, sizeof(inpcb));
	prev = (struct inpcb *) nl[N_TCB].n_value;
}

static int TCP_Scan_Next(State, RetInPcb)
int *State;
struct inpcb *RetInPcb;
{
	register struct inpcb *next;
	struct tcpcb tcpcb;

	if (inpcb.inp_next == (struct inpcb *) nl[N_TCB].n_value) {
	    return(0);	    /* "EOF" */
	}

	next = inpcb.inp_next;
	klseek((caddr_t)next);
	klread((char *)&inpcb, sizeof (inpcb));
	if (inpcb.inp_prev != prev)	   /* ??? */
		return(-1); /* "FAILURE" */
	klseek((caddr_t)inpcb.inp_ppcb);
	klread((char *)&tcpcb, sizeof (tcpcb));
	*State = tcpcb.t_state;
	*RetInPcb = inpcb;
	prev = next;
	return(1);	/* "OK" */
}

static int arptab_size, arptab_current;
static struct arptab *at=0;
static ARP_Scan_Init()
{
	if (!at) {
	    klseek(nl[N_ARPTAB_SIZE].n_value);
	    klread((char *)&arptab_size, sizeof arptab_size);

	    at = (struct arptab *) malloc(arptab_size * sizeof(struct arptab));
	}

	klseek(nl[N_ARPTAB].n_value);
	klread((char *)at, arptab_size * sizeof(struct arptab));
	arptab_current = 0;
}

static int ARP_Scan_Next(IPAddr, PhysAddr)
u_long *IPAddr;
char *PhysAddr;
{
	register struct arptab *atab;

	while (arptab_current < arptab_size) {
		atab = &at[arptab_current++];
		if (!(atab->at_flags & ATF_COM)) continue;
		*IPAddr = atab->at_iaddr.s_addr;
		bcopy((char *)&atab->at_enaddr, PhysAddr, sizeof(atab->at_enaddr));
		return(1);
	}
	return(0);	    /* "EOF" */
}


static struct ifnet *ifnetaddr, saveifnet, *saveifnetaddr;
static struct in_ifaddr savein_ifaddr;
static int saveIndex=0;
static char saveName[16];

Interface_Scan_Init()
{
	klseek(nl[N_IFNET].n_value);
	klread((char *)&ifnetaddr, sizeof ifnetaddr);
	saveIndex=0;
}

int Interface_Scan_Next(Index, Name, Retifnet, Retin_ifaddr)
int *Index;
char *Name;
struct ifnet *Retifnet;
struct in_ifaddr *Retin_ifaddr;
{
	struct ifnet ifnet;
	struct in_ifaddr *ia, in_ifaddr;
	register char *cp;
	extern char *strchr();

	while (ifnetaddr) {
	    /*
	     *	    Get the "ifnet" structure and extract the device name
	     */
	    klseek(ifnetaddr);
	    klread((char *)&ifnet, sizeof ifnet);
	    klseek((caddr_t)ifnet.if_name);
	    klread(saveName, 16);
	    saveName[15] = '\0';
	    cp = strchr(saveName, '\0');
	    *cp++ = ifnet.if_unit + '0';
	    *cp = '\0';
	    if (1 || strcmp(saveName,"lo0") != 0) {  /* XXX */
		/*
		 *  Try to find an addres for this interface
		 */
		klseek(nl[N_IN_IFADDR].n_value);
		klread((char *) &ia, sizeof(ia));
		while (ia) {
		    klseek(ia);
		    klread((char *) &in_ifaddr, sizeof(in_ifaddr));
		    if (in_ifaddr.ia_ifp == ifnetaddr) break;
		    ia = in_ifaddr.ia_next;
		}

		ifnet.if_addrlist = (struct ifaddr *)ia;     /* WRONG DATA TYPE; ONLY A FLAG */
/*		ifnet.if_addrlist = (struct ifaddr *)&ia->ia_ifa;   */  /* WRONG DATA TYPE; ONLY A FLAG */
		if (Index)
		    *Index = ++saveIndex;
		if (Retifnet)
		    *Retifnet = ifnet;
		if (Retin_ifaddr)
		    *Retin_ifaddr = in_ifaddr;
		if (Name)
		    strcpy(Name, saveName);
		saveifnet = ifnet;
		saveifnetaddr = ifnetaddr;
		savein_ifaddr = in_ifaddr;
		ifnetaddr = ifnet.if_next;
		return(1);	/* DONE */
	    }
	    ifnetaddr = ifnet.if_next;
	}
	return(0);	    /* EOF */
}

static int Interface_Scan_By_Index(Index, Name, Retifnet, Retin_ifaddr)
int Index;
char *Name;
struct ifnet *Retifnet;
struct in_ifaddr *Retin_ifaddr;
{
	int i;

	if (saveIndex != Index) {	/* Optimization! */
	    Interface_Scan_Init();
	    while (Interface_Scan_Next(&i, Name, Retifnet, Retin_ifaddr)) {
		if (i == Index) break;
	    }
	    if (i != Index) return(-1);     /* Error, doesn't exist */
	} else {
	    if (Retifnet)
		*Retifnet = saveifnet;
	    if (Retin_ifaddr)
		*Retin_ifaddr = savein_ifaddr;
	    if (Name)
		strcpy(Name, saveName);
	}
	return(0);	/* DONE */
}

static int Interface_Count=0;

static int Interface_Scan_Get_Count()
{
	if (!Interface_Count) {
	    Interface_Scan_Init();
	    while (Interface_Scan_Next((int *)0, (char *)0, (struct ifnet *)0, (struct in_ifaddr *)0) != 0)
		Interface_Count++;
	}
	return(Interface_Count);
}

static int Interface_Get_Ether_By_Index(Index, EtherAddr)
int Index;
char *EtherAddr;
{
	int i;
	struct arpcom arpcom;

	if (saveIndex != Index) {	/* Optimization! */
	    Interface_Scan_Init();
	    while (Interface_Scan_Next(&i, (char *)0, (struct ifnet *)0, (struct in_ifaddr *)0)) {
		if (i == Index) break;
	    }
	    if (i != Index) return(-1);     /* Error, doesn't exist */
	}

	/*
	 *  the arpcom structure is an extended ifnet structure which
	 *  contains the ethernet address.
	 */
	klseek(saveifnetaddr);
	klread((char *)&arpcom, sizeof arpcom);
	bcopy((char *)&arpcom.ac_enaddr, EtherAddr, sizeof(arpcom.ac_enaddr));
	return(0);	/* DONE */
}

