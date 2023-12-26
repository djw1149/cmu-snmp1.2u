#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/snmpnetstat/if.c,v 1.6 1996/11/14 15:39:46 tpt2 Exp $";
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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <signal.h>

#include "main.h"
#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"

#define	YES	1
#define	NO	0

extern	int nflag;
extern	char *interface;
extern	char *routename(), *netname();
extern	struct snmp_session *Session;
extern	struct variable_list *getvarbyname();

oid oid_ifname[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1};
static oid oid_ifinucastpkts[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 11, 1};
static oid oid_cfg_nnets[] = {1, 3, 6, 1, 2, 1, 2, 1, 0};

#define IPADENTADDR	1
#define IPADENTIFINDEX	2
#define IPADENTNETMASK	3
static oid oid_ipatad[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 1};
static oid oid_ipatix[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 2};
static oid oid_ipatnm[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 3};

#define IFNAME		2
#define IFMTU		4
#define IFADMINSTATUS	7
#define IFOPERSTATUS	8
#define INUCASTPKTS	11
#define INNUCASTPKTS	12
#define INERRORS	14
#define OUTUCASTPKTS	17
#define OUTNUCASTPKTS	18
#define OUTERRORS	20


#define	MAXIF	30		/* Some cisco routers actually have this */
				/* many interfaces...  */
struct	ipaddrs {
	struct in_addr	address; /* IP address of interface */
	int		set_address; /* initialized? */
	struct in_addr	netmask; /* netmask of interface */
	int		set_netmask; /* initialized? */
} ipaddrs[MAXIF];

/* 
 * get_interface_addrs gets the interface IP addresses and netmask of the
 * current SNMP agent by utilizing GET NEXT requests on the IP address
 * table. The results are placed in the ``ipaddrs'' array (see above). 
 */

get_interface_addrs()
{
	int ifnum;
	int status;
	oid type, *instance;
	struct ipaddrs ip;
	struct snmp_pdu *request, *response;
	struct variable_list *vp;

	bzero((char*)ipaddrs, sizeof(ipaddrs));

	request = snmp_pdu_create(GETNEXT_REQ_MSG);

	snmp_add_null_var(request, oid_ipatad, sizeof(oid_ipatad)/sizeof(oid));
	snmp_add_null_var(request, oid_ipatix, sizeof(oid_ipatix)/sizeof(oid));
	snmp_add_null_var(request, oid_ipatnm, sizeof(oid_ipatnm)/sizeof(oid));
	
	while(request){
		status = snmp_synch_response(Session, request, &response);
		if (status != STAT_SUCCESS ||
		    response->errstat != SNMP_ERR_NOERROR)
		{
			fprintf(stderr, "SNMP request failed: %s\n",
				snmp_errstring(response->errstat));
			break;
		}

		ifnum = 0;
		bzero((char*)&ip, sizeof(ip));
		instance = NULL;
#ifdef DJW /* always freed by here */
		if(request != NULL)
			snmp_free_pdu(request);
#endif /* DJW */
		request = NULL;

		for (vp = response->variables; vp; vp = vp->next_variable){
			if (bcmp((char*)vp->name, (char*)oid_ipatad,
				 sizeof(oid_ipatad)) &&
			    bcmp((char*)vp->name, (char*)oid_ipatix,
				 sizeof(oid_ipatix)) &&
			    bcmp((char*)vp->name, (char*)oid_ipatnm,
				 sizeof(oid_ipatnm)))
			{	/* Not one of the ones we want */
				continue;
			}

			if (instance != NULL){
				oid *ip, *op;
				int count;
				
				ip = instance;
				op = vp->name + 10;
				for(count = 0; count < 4; count++){
					if (*ip++ != *op++)
						break;
				}
				if (count < 4)
					continue; /* not the right */
						  /* instance, ignore */ 
			} else {
				instance = vp->name + 10; /* Offset of */
							  /* instance */
			}
			/* We now know we have the right variable*/
			
			if (request == NULL)
				request = snmp_pdu_create(GETNEXT_REQ_MSG);
			snmp_add_null_var(request, vp->name, vp->name_length);

			type = vp->name[9]; /* Which variable? */
			switch ((char)type){
			case IPADENTADDR:
				bcopy((char*)vp->val.string,
				      (char*)&ip.address,
				      sizeof(u_long));
				ip.set_address = 1;
				break;
			case IPADENTIFINDEX:
				ifnum = *vp->val.integer;
				break;
			case IPADENTNETMASK:
				bcopy((char*)vp->val.string,
				      (char*)&ip.netmask,
				      sizeof(u_long));
				ip.set_netmask = 1;
				break;
			}
		}
		if (!(ip.set_address && ip.set_netmask && ifnum)){
			if (request)
				snmp_free_pdu(request);
			request = NULL;
			continue;
		}
		if (ifnum >= MAXIF || ifnum < 0) continue;
		bcopy((char*)&ip, &ipaddrs[ifnum], sizeof(ip));
	}
}


int ifIndex[MAXIF];
oid oid_ifindex[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 1};

/*
 * get_ifindices does a GET-NEXT over all the ifIndex instances in the
 * interfaces table, recording the indices subsequently to be used when
 * GETing the interfaces table. The indices are recorded in the ifIndex
 * array.
 */

get_ifindices()
{
	struct snmp_pdu *request, *response;
	struct variable_list *vp;
	int status;
	int ix;


	request = snmp_pdu_create(GETNEXT_REQ_MSG);

	snmp_add_null_var(request, oid_ifindex,
			  sizeof(oid_ifindex)/sizeof(oid));
	
	for(ix = 1; ix < MAXIF; ix++)
	{
		status = snmp_synch_response(Session, request, &response);
		if (status != STAT_SUCCESS || response->errstat !=
		    SNMP_ERR_NOERROR)
		{ 
			fprintf(stderr, "SNMP request failed\n");
			break;
		}
		vp = response->variables;

				/* Prepare for next round of the loop */
#ifdef DJW /* always freed by here */
		snmp_free_pdu(request);
#endif /* DJW */
		request = snmp_pdu_create(GETNEXT_REQ_MSG);
		snmp_add_null_var(request, vp->name, vp->name_length);

		if (vp->name_length != sizeof(oid_ifindex)/sizeof(oid)+1 ||
		    bcmp((char*)vp->name, (char*)oid_ifindex,
			 sizeof(oid_ifindex)))
		{		/* not in this row, finished */
			break;
		}
		ifIndex[ix] = *vp->val.integer;
	}
}


/*
 * Print a description of the network interfaces.
 *
 * Returns 0 if ok, else 1 if it failed
 */
int
intpr(interval)
	int interval;
{
	oid varname[MAX_NAME_LEN], *instance, *ifentry;
	int varname_len;
	int ifnum, cfg_nnets;
	struct variable_list *var;
	char name[128];
	int mtu;
	int ipkts, ierrs, opkts, oerrs, operstatus, adminstatus;
	int failed;
	int ifnum_from_user;

	if (interval)
	    return sidewaysintpr((unsigned)interval);

	if (nflag == 1 && interface)
	{
	    ifnum_from_user = atoi(interface);
	    if (ifnum_from_user == 0) 
	    {
		if (strcmp(interface, "0") == 0)
		    fprintf(stderr, "Interface indexes can not equal 0\n");
		else
		    fprintf(stderr,
			"Numeric interface specified is not an integer (%s)\n",
			    interface);
		exit(1);
	    }
	}

	printf("%-11.11s %-5.5s %-15.15s %-15.15s %8.8s %5.5s %8.8s %5.5s",
		"Name", "Mtu", "Address", "Netmask", "Ipkts", "Ierrs",
		"Opkts", "Oerrs");
	putchar('\n');
	var = getvarbyname(Session, oid_cfg_nnets, sizeof(oid_cfg_nnets) / sizeof(oid));
	if (var)
	    cfg_nnets = *var->val.integer;
	else
	{
	    fprintf(stderr, "SNMP request failed\n");
	    return 1;
	}
	get_interface_addrs();
	get_ifindices();
	bcopy((char *)oid_ifname, (char *)varname, sizeof(oid_ifname));
	varname_len = sizeof(oid_ifname) / sizeof(oid);
	ifentry = varname + 9;
	instance = varname + 10;
	for (ifnum = 1; ifnum <= cfg_nnets; ifnum++) {
		register char *cp;
		char *strchr();

		*name = mtu = 0;
		ipkts = ierrs = opkts = oerrs = operstatus = adminstatus = 0;
		*instance = ifIndex[ifnum];
#ifdef ONE_AT_A_TIME
		*ifentry = IFNAME;
		var = getvarbyname(Session, varname, varname_len);
		if (var){
		    bcopy((char *)var->val.string, name, var->val_len);
		    name[var->val_len] = 0;
		}
		*ifentry = IFMTU;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    mtu = *var->val.integer;
		*ifentry = IFADMINSTATUS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    adminstatus = *var->val.integer;
		*ifentry = IFOPERSTATUS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    operstatus = *var->val.integer;
		*ifentry = INUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    ipkts = *var->val.integer;
		*ifentry = INNUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    ipkts += *var->val.integer;
		*ifentry = INERRORS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    ierrs = *var->val.integer;
		*ifentry = OUTUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    opkts = *var->val.integer;
		*ifentry = OUTNUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    opkts += *var->val.integer;
		*ifentry = OUTERRORS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    oerrs = *var->val.integer;
#else /* !ONE_AT_A_TIME */
	{
		struct snmp_pdu *request, *response, *newrequest;
		int status;
		struct variable_list *vp;
		oid type;

		request = snmp_pdu_create(GET_REQ_MSG);

		*ifentry = IFNAME;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = IFMTU;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = IFADMINSTATUS;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = IFOPERSTATUS;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = INUCASTPKTS;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = INNUCASTPKTS;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = INERRORS;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = OUTUCASTPKTS;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = OUTNUCASTPKTS;
		snmp_add_null_var(request, varname, varname_len);
		*ifentry = OUTERRORS;
		snmp_add_null_var(request, varname, varname_len);

		failed = 0;
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
			if (response->errstat == SNMP_ERR_NOSUCHNAME)
			{
				/* Some Unix agent do not implement all the */
				/* variables we ask for. Allow for 4 */
				/* missing variables...  */
				if(failed++ < 4)
				{
					newrequest = snmp_fix_pdu(response,
								  GET_REQ_MSG);
				/* Why does not this work? */
				/* request appears to be clobbered (!), */
				/* but only second time around! */
					/* if(request) */
					/*	snmp_free_pdu(request);	*/
					request = newrequest;
					goto again;
				}
			}
			fprintf(stderr, "SNMP request failed: %s\n",
				snmp_errstring(response->errstat));
			break;
		}
		ipkts = opkts = 0;
		for (vp = response->variables; vp; vp = vp->next_variable){
			type = vp->name[9];
			switch ((char)type){
			case IFNAME:
				bcopy((char*)vp->val.string, name,
				      vp->val_len);
				name[vp->val_len] = 0;
				break;
			case IFMTU:
				mtu = *vp->val.integer;
				break;
			case IFADMINSTATUS:
				adminstatus = *vp->val.integer;
				break;
			case IFOPERSTATUS:
				operstatus = *vp->val.integer;
				break;
			case INUCASTPKTS:
				ipkts += *vp->val.integer;
				break;
			case INNUCASTPKTS:
				ipkts += *vp->val.integer;
				break;
			case INERRORS:
				ierrs = *vp->val.integer;
				break;
			case OUTUCASTPKTS:
				opkts += *vp->val.integer;
				break;
			case OUTNUCASTPKTS:
				opkts += *vp->val.integer;
				break;
			case OUTERRORS:
				oerrs = *vp->val.integer;
				break;
			}
		}
	}
#endif /* ONE_AT_A_TIME */

		name[15] = '\0';
		if (interface)
		    if (nflag == 0)
		    {
			if (strcmp(name, interface) != 0)
			    continue;
		    }
		    else if (ifnum != ifnum_from_user)
			continue;

		cp = strchr(name, '\0');
		if (operstatus != MIB_IFSTATUS_UP)
			if (adminstatus == MIB_IFSTATUS_UP)
				*cp++ = '*';
			else
				*cp++ = '@';
		*cp = '\0';
		printf("%-11.11s %-5d ", name, mtu);
		printf("%-15.15s ", ipaddrs[ifIndex[ifnum]].set_address ?
		       inet_ntoa(ipaddrs[ifIndex[ifnum]].address)
		       : "none");
		printf("%-15.15s ", ipaddrs[ifIndex[ifnum]].set_netmask ?
		       inet_ntoa(ipaddrs[ifIndex[ifnum]].netmask)
		       : "none");
		printf("%8d %5d %8d %5d",
		    ipkts, ierrs,
		    opkts, oerrs);
		putchar('\n');
	}
	return 0;
}

struct	iftot {
	char	ift_name[128];		/* interface name */
	int	ift_ip;			/* input packets */
	int	ift_ie;			/* input errors */
	int	ift_op;			/* output packets */
	int	ift_oe;			/* output errors */
	int	ift_co;			/* collisions */
} iftot[MAXIF];

u_char	signalled;			/* set if alarm goes off "early" */

/*
 * Print a running summary of interface statistics.
 * Repeat display every interval seconds, showing statistics
 * collected over that interval.  Assumes that interval is non-zero.
 * First line printed at top of screen is always cumulative.
 *
 * Returns 0 if ok (or may never return), else 1 if it failed
 */
sidewaysintpr(interval)
	unsigned interval;
{
	register struct iftot *ip, *total;
	register int line;
	struct iftot *lastif, *sum, *interesting, ifnow, *now = &ifnow;
	int oldmask;
	int catchalarm();
	struct variable_list *var;
	oid varname[MAX_NAME_LEN], *instance, *ifentry;
	int varname_len;
	int ifnum, cfg_nnets;
	char *strchr();
	int ifnum_from_user;
	sigset_t block, oblock;
	struct sigaction act, oact;


	if (nflag == 1)
	{
	    if (interface == NULL) 
	    {
		fprintf(stderr,
		  "An interface must be specified with the -n and -I flags\n");
		exit(1);
	    }	    

	    ifnum_from_user = atoi(interface);
	    if (ifnum_from_user == 0) 
	    {
		if (strcmp(interface, "0") == 0)
		    fprintf(stderr, "Interface indexes can not equal 0\n");
		else
		    fprintf(stderr,
			"Numeric interface specified is not an integer (%s)\n",
			    interface);
		exit(1);
	    }
	}
		
	lastif = iftot;
	sum = iftot + MAXIF - 1;
	total = sum - 1;
	interesting = NULL;
	
	var = getvarbyname(Session, oid_cfg_nnets, sizeof(oid_cfg_nnets) / sizeof(oid));
	if (var)
	    cfg_nnets = *var->val.integer;
	else
	{
	    fprintf(stderr, "SNMP request failed\n");
	    return 1;
	}
	bcopy((char *)oid_ifname, (char *)varname, sizeof(oid_ifname));
	varname_len = sizeof(oid_ifname) / sizeof(oid);
	for (ifnum = 1, ip = iftot; ifnum <= cfg_nnets; ifnum++) {
	    char *cp;
	    
	    ip->ift_name[0] = '(';
	    varname[10] = ifnum;
	    var = getvarbyname(Session, varname, varname_len);
	    if (var){
		bcopy((char *)var->val.string, ip->ift_name + 1, var->val_len);
	    }
	    if (nflag == 0)
	    {
		if (interface && strcmp(ip->ift_name + 1, interface) == 0)
		    interesting = ip;
	    }
	    else if (ifnum == ifnum_from_user)
		interesting = ip;
	    ip->ift_name[15] = '\0';
	    cp = strchr(ip->ift_name, '\0');
	    sprintf(cp, ")");
	    ip++;
	    if (ip >= iftot + MAXIF - 2)
		break;
	}
	lastif = ip;

	if (interesting == NULL) 
	    if (interface == NULL)
		interesting = iftot; /* default */
	    else
	    {
		fprintf(stderr,
			"Interface %s could not be found on the device\n",
			interface);
		exit(1);
	    }

	(void)signal(SIGALRM, catchalarm);
	signalled = NO;
	(void)alarm(interval);
banner:
	printf("    input   %-13.13s  output  ", interesting->ift_name);
	if (lastif - iftot > 0)
		printf("     input  (Total)         output");
	for (ip = iftot; ip < iftot + MAXIF; ip++) {
		ip->ift_ip = 0;
		ip->ift_ie = 0;
		ip->ift_op = 0;
		ip->ift_oe = 0;
		ip->ift_co = 0;
	}
	putchar('\n');
	printf("%8.8s %5.5s %8.8s %5.5s %5.5s ",
		"packets", "errs", "packets", "errs", "colls");
	if (lastif - iftot > 0)
		printf("%8.8s %5.5s %8.8s %5.5s %5.5s ",
			"packets", "errs", "packets", "errs", "colls");
	putchar('\n');
	fflush(stdout);
	line = 0;
loop:
	sum->ift_ip = 0;
	sum->ift_ie = 0;
	sum->ift_op = 0;
	sum->ift_oe = 0;
	sum->ift_co = 0;
	bcopy((char *)oid_ifinucastpkts, (char *)varname, sizeof(oid_ifinucastpkts));
	varname_len = sizeof(oid_ifinucastpkts) / sizeof(oid);
	ifentry = varname + 9;
	instance = varname + 10;
	for (ifnum = 1, ip = iftot; ifnum <= cfg_nnets && ip < lastif; ip++, ifnum++) {
		bzero((char *)now, sizeof(*now));
		*instance = ifnum;
		*ifentry = INUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_ip = *var->val.integer;
		*ifentry = INNUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_ip += *var->val.integer;
		*ifentry = INERRORS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_ie = *var->val.integer;
		*ifentry = OUTUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_op = *var->val.integer;
		*ifentry = OUTNUCASTPKTS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_op += *var->val.integer;
		*ifentry = OUTERRORS;
		var = getvarbyname(Session, varname, varname_len);
		if (var)
		    now->ift_oe = *var->val.integer;

		if (ip == interesting)
			printf("%8d %5d %8d %5d %5d ",
				now->ift_ip - ip->ift_ip,
				now->ift_ie - ip->ift_ie,
				now->ift_op - ip->ift_op,
				now->ift_oe - ip->ift_oe,
				now->ift_co - ip->ift_co);
		ip->ift_ip = now->ift_ip;
		ip->ift_ie = now->ift_ie;
		ip->ift_op = now->ift_op;
		ip->ift_oe = now->ift_oe;
		ip->ift_co = now->ift_co;
		sum->ift_ip += ip->ift_ip;
		sum->ift_ie += ip->ift_ie;
		sum->ift_op += ip->ift_op;
		sum->ift_oe += ip->ift_oe;
		sum->ift_co += ip->ift_co;
	}
	if (lastif - iftot > 0)
		printf("%8d %5d %8d %5d %5d ",
			sum->ift_ip - total->ift_ip,
			sum->ift_ie - total->ift_ie,
			sum->ift_op - total->ift_op,
			sum->ift_oe - total->ift_oe,
			sum->ift_co - total->ift_co);
	*total = *sum;
	putchar('\n');
	fflush(stdout);
	line++;

	(void)sigemptyset(&block);
	(void)sigaddset(&block, SIGALRM);
	if (sigprocmask(SIG_BLOCK, &block, &oblock) < 0)
	  perror("sigprocmask");
/* 	oldmask = sigblock(sigmask(SIGALRM)); */
	if (! signalled) {
		sigpause(0);
	}
/*	sigsetmask(oldmask); */
	(void)sigprocmask(SIG_SETMASK, &block, (sigset_t *)NULL);
#ifdef SA_RESTART         /* make restartable */
	act.sa_flags = SA_RESTART;
#endif   /* SA_RESTART */
	if (sigaction(SIGALRM, &act, &oact) < 0)
	  return(1); /*SIG_ERR);*/

	signalled = NO;
	(void)alarm(interval);
	if (line == 21)
		goto banner;
	goto loop;
	/*NOTREACHED*/
}

/*
 * Called if an interval expires before sidewaysintpr has completed a loop.
 * Sets a flag to not wait for the alarm.
 */
catchalarm()
{
	signalled = YES;
}
