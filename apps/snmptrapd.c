/*
 * snmptrapd.c - receive and log snmp traps
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

#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmptrapd.c,v 1.12 1995/02/16 13:48:35 djw Exp $";
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/time.h>
#include <errno.h>
#include <syslog.h>

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"

#define Target_FindByIP(ip) Target_FindByIP1(ip, target_list)
extern int *target_list;
extern char *g_logDir;
extern char g_trapTextDir[];

extern char *GetHostname();
extern int g_alternatePrint; /* $$$ added by R.Lebow to provide functionality
			    * requested by T20 group.  This adds a time 
			    * string and other pretty print features to the
			    * trap text printed by PrintTraps().  T20 people
			    * will use it as a hidden feature that is invoked
			    * by the -v switch. Note that the DM doesn't expect
			    * the traps to printed using this format.
			    */

#ifndef BSD4_3

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif /* BSD4_3 */

extern int longncmp();
extern void print_standard_trap();
extern char *build_vars_msg();

/* $$$ added following  rlebow */
extern char *arbitraryDate ();
extern char *stripTrailingBlanks ();
extern char *stripExtraBlanks ();
extern char *stripTimeString ();
/* end rlebow */

#ifndef EIGHTBIT_SUBIDS
/* typedef u_long  oid; */
int (*oidcmp)() = longncmp ;
#else
/* typedef u_char  oid; */
int (*oidcmp)() = memcmp;
#endif

extern int  errno;
int	snmp_dump_packet = 0;
int Print = 0;
int Null_termination = 0;

#ifndef BBN_VENDOR 
#define BBN_VENDOR    14    /* BBN number in private MIB */
#define BBN_GW         5
#define T20_GW        10
#endif /* BBN_VENDOR */

oid t20oid[] = { 1,3,6,1,4,1,14,5,10} ;

#define T20_LEN  ( sizeof t20oid / sizeof t20oid[0] )

char *
trap_description(trap)
    int trap;
{
    switch(trap)
    {
	case SNMP_TRAP_COLDSTART:
	    return "Cold Start";

	case SNMP_TRAP_WARMSTART:
	    return "Warm Start";

	case SNMP_TRAP_LINKDOWN:
	    return "Link Down";

	case SNMP_TRAP_LINKUP:
	    return "Link Up";

	case SNMP_TRAP_AUTHFAIL:
	    return "Authentication Failure";

	case SNMP_TRAP_EGPNEIGHBORLOSS:
	    return "EGP Neighbor Loss";

	case SNMP_TRAP_ENTERPRISESPECIFIC:
	    return "Enterprise Specific";

	default:
	    return "Unknown Type";
    }
}

char *
uptime_string(timeticks, buf)
    register u_long timeticks;
    char *buf;
{
    int	seconds, minutes, hours, days;

    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (days == 0)
    {
	sprintf(buf, "%d:%02d:%02d", hours, minutes, seconds);
    } 
    else if (days == 1) 
    {
	sprintf(buf, "%d day, %d:%02d:%02d", days, hours, minutes, seconds);
    } 
    else 
    {
	sprintf(buf, "%d days, %d:%02d:%02d", days, hours, minutes, seconds);
    }
    return buf;
}

int snmp_input(op, session, reqid, pdu, magic)
    int op;
    struct snmp_session *session;
    int reqid;			/* (U) */
    struct snmp_pdu *pdu;
    void *magic;
{
    struct variable_list *vars;
    char buf[64];
    char syslogString[4096]; /* Hoping this is more than big enough for */
                             /* varbuf and var bindings.                */

    char varbuf[2048];       /* used to build a messages for writing trap */
                             /* and varbindings to syslog.                */

    bzero(varbuf, sizeof(varbuf));

    if (op == RECEIVED_MESSAGE && pdu->command == TRP_REQ_MSG) 
    {
	if (Print)	
	{
	    if (pdu->trap_type != SNMP_TRAP_ENTERPRISESPECIFIC || 
		(pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC &&
		 oidcmp(t20oid, pdu->enterprise, T20_LEN) != 0))	
	    {
		print_standard_trap(pdu);
	    }
	    else
	    {
		/* HMP traps */
		uptime_string (pdu->time, buf);
		for(vars = pdu->variables; vars; vars = vars->next_variable)  
		{
		    PrintTraps(pdu->agent_addr.sin_addr, 
			       vars->val.string, vars->val_len, 
			       pdu->time, buf, NULL);
		}
		if (Null_termination)
		    putchar('\0');
	    }		    
	    fflush(stdout);	/* $$$ djw- added */
	}
	else			/* not printing  */
	{
	    if (pdu->trap_type != SNMP_TRAP_ENTERPRISESPECIFIC || 
		(pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC &&
		 oidcmp(t20oid, pdu->enterprise, T20_LEN) != 0))	
	    {

	      if (g_alternatePrint == FALSE) 
	      {

		sprintf(varbuf, "%s: %s Trap (%d) Uptime: %s", 
		       inet_ntoa(pdu->agent_addr.sin_addr),
		       trap_description(pdu->trap_type), pdu->specific_type, 
		       uptime_string(pdu->time, buf));

		vars = pdu->variables;

#ifdef SEPERATE_LINES

		syslog(LOG_WARNING, "%s\n", varbuf);

		/* $$$ rlebow
		 * print the var bindings.  NOTE that the syslog utility 
		 * appears to delete everything following a new line character,
		 * therefore you must have separate calls to syslog if you 
		 * wish to separate each var binding in a readable manner.
		 */

		if (vars)
		  for(; vars; vars = vars->next_variable)
		  {
		    sprint_variable(varbuf, 
				    vars->name, vars->name_length, vars);

		    syslog(LOG_WARNING, "%s\n", varbuf);
		  }
#else
		/* 
		 * $$$ rlebow
		 * The noc wants the var bindings to appear as one line in
		 * the syslog therefore I will bundle them up into one buffer 
		 * and see what happens.  There might be some syslog message
		 * length limitation that makes this a waste of time.  
		 */

		if (vars) 
		{
		  sprintf(syslogString, "%s\t%s", 
			  varbuf, build_vars_msg(vars));
		  syslog(LOG_WARNING, "%s", syslogString);
		}

#endif SEPERATE_LINES



	      }
	      else
	      {
		/* $$$ added by rlebow */
		/* format the standard trap differently for the t20 guys */

		uptime_string(pdu->time, buf);
		stripTimeString(buf);

		sprintf(varbuf,
		       "%-15.15s %s (%s) T---: %s Trap (%d)", 
		       GetHostname(pdu->agent_addr.sin_addr),
		       arbitraryDate(time((time_t *)NULL)),
		       buf,
		       trap_description(pdu->trap_type), 
		       pdu->specific_type);

		/* strip out extra blanks */
		stripExtraBlanks(varbuf);

		vars = pdu->variables;

#ifdef SEPERATE_LINES

		syslog(LOG_WARNING, "%s\n", varbuf);

		/* $$$ rlebow
		 * print the var bindings.  NOTE that the syslog utility 
		 * appears to delete everything following a new line character,
		 * therefore you must have separate calls to syslog if you 
		 * wish to separate each var binding in a readable manner.
		 */

		if (vars)
		  for(; vars; vars = vars->next_variable)
		  {
		    sprint_variable(varbuf, 
				    vars->name, vars->name_length, vars);
		    syslog(LOG_WARNING, "%s\n", varbuf);
		  }
#else
		/* 
		 * $$$ rlebow
		 * The noc wants the var bindings to appear as one line in
		 * the syslog therefore I will bundle them up into one buffer 
		 * and see what happens.  There might be some syslog message
		 * length limitation that makes this a waste of time.  
		 */

		if (vars) 
		{
		  sprintf(syslogString, "%s\t%s", 
			  varbuf, build_vars_msg(vars));
		  syslog(LOG_WARNING, "%s", syslogString);
		}

#endif SEPERATE_LINES

	      }
	    }
	    else	/* t20 enterprise specific trap */
	    {
		/* HMP traps */
		uptime_string (pdu->time, buf);
		for(vars = pdu->variables; vars; vars = vars->next_variable)  
		{
		    PrintTraps(pdu->agent_addr.sin_addr, 
			       vars->val.string, vars->val_len, 
			       pdu->time, buf, syslogString);
		    syslog(LOG_WARNING, "%s", syslogString);
		} /* for  */
	    } /* t20 specific trap */
	} /* not printing */
    } 
    else if (op == TIMED_OUT)
    {
	printf("Timeout: This shouldn't happen!\n");
    }
    return;
}

/*
 * print_standard_trap(struct snmp_pdu * pdu)
 * 
 * print a standard SNMP trap 
 */

void print_standard_trap(pdu)
register struct snmp_pdu * pdu ;
{
    register struct variable_list * vars;
    char buf[2048], buf2[80];



     if (g_alternatePrint == FALSE) 
     {
       printf("%s: %s Trap (%d) Uptime: %s", 
	   inet_ntoa(pdu->agent_addr.sin_addr),
	   trap_description(pdu->trap_type), pdu->specific_type, 
	   uptime_string(pdu->time, buf));

     }
     else
     {
       /* $$$ added by rlebow */
       /* format the standard trap differently for the t20 guys */
       uptime_string(pdu->time, buf2);
       stripTimeString(buf2);

       sprintf(buf,
	       "%-15.15s %s (%s) T---: %s Trap (%d)", 
	       GetHostname(pdu->agent_addr.sin_addr),
	       arbitraryDate(time((time_t *)NULL)),
	       buf2,
	       trap_description(pdu->trap_type), 
	       pdu->specific_type);

       
       /* strip out extra blanks and print */
       stripExtraBlanks(buf);
       printf(buf);
     }


    vars = pdu->variables;
      
    if (vars)
    {
      putchar('\n');
      for(; vars; vars = vars->next_variable)
      {
	sprint_variable(buf, vars->name, vars->name_length, vars);
	if (vars->next_variable == NULL && Null_termination)
	{
	  buf[strlen(buf) - 1] = '\0';
	  fputs(buf, stdout);
	  putchar('\0');
	}
	else
	  fputs(buf, stdout);
      }
    }
    else if (Null_termination)
      putchar('\0');
    else       
      putchar('\n');
}

int longncmp(v1, v2, n)
register long * v1, * v2;
register int n ;
{
    register long v ;

    while(n--)
    {
	if((v = (*v1++ - *v2++)) != 0)
	    return v;
    }
    return 0;
}

main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session session, *ss;
    int	arg;
    int count, numfds, block;
    fd_set fdset;
    struct timeval timeout, *tvp;
    int dest_port = SNMP_TRAP_PORT;


    init_syslog();
    init_mib();
    /*
     * usage: snmptrapd [-p] [-d] [-t] [-N] [-P port#]
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
		case 'd':
		    snmp_dump_packet++;
		    break;
/*		case 'l':
/*		    arg++;
/*		    strcpy (g_logDir, argv[argc]);
/*		    break;
*/
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
		case 'N':
		    Null_termination++;
		    Print++;
		    break;
		case 'p':
		    Print++;
		    break;
		case 't':
		    if (arg == argc - 1)
		    {
			printf("No value given to -t option\n");
			exit(1);
		    }
		    strcpy (g_trapTextDir, argv[++arg]);
		    break;
		case 'v':
		    g_alternatePrint = TRUE;
		    break;
		default:
		    printf("invalid option: -%c\n", argv[arg][1]);
		    printf("Usage: snmptrapd [-p] [-d] [-t] [-N] [-P port#]\n");
		    exit(-1); /* $$$ rlebow, added exit here */
		    break;
	    }
	    continue;
	}
    }

    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = NULL;
    session.community = NULL;
    session.community_len = 0;
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.authenticator = NULL;
    session.callback = snmp_input;
    session.callback_magic = NULL;
    session.local_port = dest_port;
    ss = snmp_open(&session);
    if (ss == NULL){
	printf("Couldn't open snmp\n");
	exit(-1);
    }

    InitProcTrap ();

    while(1){
	numfds = 0;
	FD_ZERO(&fdset);
	block = 1;
	tvp = &timeout;
	timerclear(tvp);
	snmp_select_info(&numfds, &fdset, tvp, &block);
	if (block == 1)
	    tvp = NULL;	/* block without timeout */
	count = select(numfds, &fdset, 0, 0, tvp);
	if (count > 0)
	{
	    snmp_read(&fdset);
	} 
	else switch(count)
	{
	    case 0:
		snmp_timeout();
		break;
	    case -1:
		if (errno == EINTR){
		    continue;
		} else {
		    perror("select");
		}
		return -1;
	    default:
		printf("select returned %d\n", count);
		return -1;
	}
    }

}


/* 
 * take all the varbindings and push them into a single buffer.
 * replace any new line characters with tab characters. 
 */

char *build_vars_msg(vars)
     struct variable_list *vars;
{
   int totalsize=0, x;
   char tmpbuf[512];
   static char syslogbuf[2048]; /* hoping this is long enough */
   char *tmpP=syslogbuf;
   
   /* lets build each varbinding and set the pointers. */
   for(; vars; vars = vars->next_variable)
     {
       sprint_variable(tmpbuf, 
		       vars->name, vars->name_length, vars);

       if ((totalsize += strlen(tmpbuf)) > (sizeof(syslogbuf) -1))
       {
	 syslog(LOG_WARNING, 
		"Internal buffer too small to write all variable bindings.");
	 break;
       }
       else
       {
	 /* 
	  * copy the var binding into the array and move up the pointer for
	  * the next string 
	  */
	 strcpy(tmpP, tmpbuf); 
	 tmpP += strlen(tmpbuf);
       }
     }

   /* 
    * sprint_variable always tags a newline on the end of the binding 
    * so lets replace all newlines with tab characters.
    */
   for (x = 0; x < totalsize; x++)
     if (syslogbuf[x] == '\n')
       syslogbuf[x] = '\t';

   /* 
    * now go back and replace that last tab with a newline.  Looks 
    * gross but should make snmptrapd be faster than checking every 
    * time to see if x == totalsize -1 
    */
   syslogbuf[totalsize -1] = '\n';

   return(syslogbuf);
}


init_syslog()
{
/*
 * These definitions handle 4.2 systems without additional syslog facilities.
 */

#ifndef LOG_CONS
#define LOG_CONS	0	/* Don't bother if not defined... */
#endif

#ifndef LOG_LOCAL0
#define LOG_LOCAL0	0
#endif
    /*
     * All messages will be logged to the local0 facility and will be sent to
     * the console if syslog doesn't work.
     */

    openlog("snmptrapd", LOG_CONS, LOG_LOCAL0);
    syslog(LOG_INFO, "Starting snmptrapd");
}


