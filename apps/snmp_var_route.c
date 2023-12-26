#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmp_var_route.c,v 1.4 1996/11/14 15:16:07 tpt2 Exp $";
#endif

/*
 * snmp_var_route.c - return a pointer to the named variable.
 *
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University
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

#define GATEWAY			/* MultiNet is always configured this way! */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <syslog.h>
/*#include <sys/mbuf.h>*/
#include "mbuf.h"
#include <net/if.h>
#define KERNEL		/* to get routehash and RTHASHSIZ */
#include <net/route.h>
#undef	KERNEL
#define rt_unit rt_hash		       /* Reuse this field for device # */
#include <nlist.h>
#ifndef NULL
#define NULL 0
#endif

#define CACHE_TIME (120)	    /* Seconds */

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "mib.h"
#include "snmp_vars.h"

static struct rtentry **rthead=0;
static int rtsize=0, rtalloc=0;

static struct nlist nl[] = {
#define N_RTHOST       0
	{ "_rthost" },
#define N_RTNET        1
	{ "_rtnet" },
#define N_RTHASHSIZE	2
	{ "_rthashsize" },
	0,
};

u_char *
var_ipRouteEntry(vp, name, length, exact, var_len, access_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output strings */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			*access_method; /* OUT - 1 if function, 0 if char pointer. */
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.21.1.1.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
    register int Save_Valid, result, RtIndex;
    static int saveNameLen=0, saveExact=0, saveRtIndex=0;
    static oid saveName[14], Current[14];
    u_char *cp;
    oid *op;


    /*
     *	OPTIMIZATION:
     *
     *	If the name was the same as the last name, with the possible
     *	exception of the [9]th token, then don't read the routing table
     *
     */

    if ((saveNameLen == *length) && (saveExact == exact)) {
	register int temp=name[9];
	name[9] = 0;
	Save_Valid = (compare(name, *length, saveName, saveNameLen) == 0);
	name[9] = temp;
    } else Save_Valid = 0;

    if (Save_Valid) {
	register int temp=name[9];    /* Fix up 'lowest' found entry */
	bcopy((char *) Current, (char *) name, 14 * sizeof(oid));
	name[9] = temp;
	*length = 14;
	RtIndex = saveRtIndex;
    } else {
	/* fill in object part of name for current (less sizeof instance part) */

	bcopy((char *)vp->name, (char *)Current, (int)(vp->namelen - 4) * sizeof(oid));

#if 0
	/*
	 *  Only reload if this is the start of a wildcard
	 */
	if (*length < 14) {
	    Route_Scan_Reload();
	}
#else
        Route_Scan_Reload();
#endif
	for(RtIndex=0; RtIndex < rtsize; RtIndex++) {
	    cp = (u_char *)&(((struct sockaddr_in *) &(rthead[RtIndex]->rt_dst))->sin_addr.s_addr);
	    op = Current + 10;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;

	    result = compare(name, *length, Current, 14);
	    if ((exact && (result == 0)) || (!exact && (result < 0)))
		break;
	}
	if (RtIndex >= rtsize) return(NULL);
	/*
	 *  Save in the 'cache'
	 */
	saveNameLen = sizeof(saveName) / sizeof(saveName[0]);
	if (*length < saveNameLen) saveNameLen = *length;
	bcopy((char *) name, (char *) saveName, saveNameLen * sizeof(oid));
	saveName[9] = '\0';
	saveExact = exact;
	saveRtIndex = RtIndex;
	/*
	 *  Return the name
	 */
	bcopy((char *) Current, (char *) name, 14 * sizeof(oid));
	*length = 14;
    }

    *access_method = 0;
    *var_len = sizeof(long_return);
    switch(vp->magic){
	case IPROUTEDEST:
	    return(u_char *) &((struct sockaddr_in *) &rthead[RtIndex]->rt_dst)->sin_addr.s_addr;
	case IPROUTEIFINDEX:
	    long_return = rthead[RtIndex]->rt_unit;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC1:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_GATEWAY) ? 1 : 0;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC2:
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC3:
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC4:
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTENEXTHOP:
	    return(u_char *) &((struct sockaddr_in *) &rthead[RtIndex]->rt_gateway)->sin_addr.s_addr;
	case IPROUTETYPE:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_GATEWAY) ? 4 : 3;
	    return (u_char *)&long_return;
	case IPROUTEPROTO:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_DYNAMIC) ? 4 : 2;
	    return (u_char *)&long_return;
	case IPROUTEAGE:
	    long_return = 0;
	    return (u_char *)&long_return;
	default:
	    ERROR("");
   }
   return NULL;
}

init_routes(){

/*    nlist("/vmunix",nl);*/
      nlist("/dev/ksyms", nl);
}

static Route_Scan_Reload()
{
	struct mbuf **routehash, mb;
	register struct mbuf *m;
	struct ifnet ifnet;
	struct rtentry *rt;
	int i, table, qsort_compare();
	register char *cp;
	char name[16], temp[16];
	static int Time_Of_Last_Reload=0;
	struct timeval now;
	int hashsize;

	gettimeofday(&now, (struct timezone *)0);
	if (Time_Of_Last_Reload+CACHE_TIME > now.tv_sec)
	    return;
	Time_Of_Last_Reload =  now.tv_sec;

	/*
	 *  Makes sure we have SOME space allocated for new routing entries
	 */
	if (!rthead) {
	    rthead = (struct rtentry **) malloc(100 * sizeof(struct rtentry *));
	    bzero((char *)rthead, 100 * sizeof(struct rtentry *));
	    rtalloc = 100;
	}

	for (table=N_RTHOST; table<=N_RTNET; table++) {
	    klseek(nl[N_RTHASHSIZE].n_value);
	    klread((char *)&hashsize, sizeof(hashsize));
	    routehash = (struct mbuf **)malloc(hashsize * sizeof(struct mbuf *));
	    klseek(nl[table].n_value);
	    klread((char *)routehash, hashsize * sizeof(struct mbuf *));
	    for (i = 0; i < hashsize; i++) {
		if (routehash[i] == 0)
			continue;
		m = routehash[i];
		while (m) {
		    /*
		     *	Dig the route out of the kernel...
		     */
		    klseek(m);
		    klread(&mb, sizeof (mb));
		    m = mb.m_next;
		    rt = mtod(&mb, struct rtentry *);
		    if (rt->rt_ifp != 0) {
			klseek(rt->rt_ifp);
			klread((char *)&ifnet, sizeof (ifnet));
			klseek((int)ifnet.if_name);
			klread(name, 16);
			name[15] = '\0';
			cp = (char *) strchr(name, '\0');
			*cp++ = ifnet.if_unit + '0';
			*cp = '\0';
/*			if (strcmp(name,"lo0") == 0) continue; */
			Interface_Scan_Init();
			while (Interface_Scan_Next(&rt->rt_unit, temp, 0, 0) != 0) {
			    if (strcmp(name, temp) == 0) break;
			}
		    }
		    /*
		     *	Allocate a block to hold it and add it to the database
		     */
		    if (rtsize >= rtalloc) {
			rthead = (struct rtentry **) realloc((char *)rthead, 2 * rtalloc * sizeof(struct rtentry *));
			bzero((char *) &rthead[rtalloc], rtalloc * sizeof(struct rtentry *));
			rtalloc *= 2;
		    }
		    if (!rthead[rtsize])
			rthead[rtsize] = (struct rtentry *) malloc(sizeof(struct rtentry));
		    /*
		     *	Add this to the database
		     */
		    bcopy((char *)rt, (char *)rthead[rtsize], sizeof(struct rtentry));
		    rtsize++;
		}
	    }
	}
	/*
	 *  Sort it!
	 */
	qsort((char *)rthead,rtsize,sizeof(rthead[0]),qsort_compare);
}



/*
 *	Create a host table
 */
static int qsort_compare(r1,r2)
struct rtentry **r1, **r2;
{
	register u_long dst1 = ntohl(((struct sockaddr_in *) &((*r1)->rt_dst))->sin_addr.s_addr);
	register u_long dst2 = ntohl(((struct sockaddr_in *) &((*r2)->rt_dst))->sin_addr.s_addr);

	/*
	 *	Do the comparison
	 */
	if (dst1 == dst2) return(0);
	if (dst1 > dst2) return(1);
	return(-1);
}
