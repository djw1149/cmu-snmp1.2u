#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmpdelta.c,v 1.2 1992/07/29 18:16:46 djw Exp $";
#endif

/*
 * snmpdelta.c - Monitor delta's in integer valued SNMP variables
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
#include <sys/time.h>


#include "snmp.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"

extern int  errno;
int	snmp_dump_packet = 0;

log(file, message)
    char *file;
    char *message;
{
    FILE *fp;
    long timeofday;
    char buf[30];

    fp = fopen(file, "a");
    if (fp == NULL){
        fprintf(stderr, "Couldn't open %s\n", file);
        return;
    }
    fprintf(fp, "%s\n", message);
    fclose(fp);
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
    long values[128];
    long value;
    int period = 1;
    int deltat = 0, timestamp = 0, fileout = 0;
    long last_time = 0;
    long this_time;
    long delta_time;
    char *cp, buf[256];
    oid name[MAX_NAME_LEN];
    int name_length;
    struct timeval tv;
    struct tm tm;
    char timestring[64], label[256], outstr[256];
    int status;

    init_mib();
    /*
     * usage: snmpdelta gateway-name community-name [-f] [-s] [-t] [-p period]
      variable list ..
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
		case 'd':
		    snmp_dump_packet++;
		    break;
		case 'p':
		    period = atoi(argv[++arg]);
		    break;
		case 't':
		    deltat = 1;
		    break;
		case 's':
		    timestamp = 1;
		    break;
		  case 'f':
		    fileout = 1;
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
	printf("usage: snmpdelta [-f] [-s] [-t] [-p period] [-d] \\\n\
    gateway-name community-name object-identifier [object-identifier ...]\n");
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

    for(count = 0; count < current_name; count++)
      values[count] = 0;

    while(1){
      pdu = snmp_pdu_create(GET_REQ_MSG);
      
      if (deltat){
	name_length = MAX_NAME_LEN;
	if (!read_objid(".iso.org.dod.internet.mgmt.1.system.sysUptime.0", name, &name_length)){
	  printf("Invalid object identifier: %s\n", "system.sysUptime.0");
	}
	snmp_add_null_var(pdu, name, name_length);
      }	
      for(count = 0; count < current_name; count++){
	name_length = MAX_NAME_LEN;
	if (!read_objid(names[count], name, &name_length)){
	  printf("Invalid object identifier: %s\n", names[count]);
	}
	
	snmp_add_null_var(pdu, name, name_length);
      }
      
    retry:
      status = snmp_synch_response(ss, pdu, &response);
      if (status == STAT_SUCCESS){
	if (response->errstat == SNMP_ERR_NOERROR){
	  vars = response->variables;
	  if (deltat){
	    if (!vars){
	      printf("Missing variable in reply\n");
	    } else {
	      delta_time = *(vars->val.integer) - last_time;
	      this_time = *(vars->val.integer);
	    }
	    vars = vars->next_variable;
	  }	    
	  for(count = 0; count < current_name; count++){
	    if (!vars){
	      printf("Missing variable in reply\n");
	      break;
	    }
	    value = *(vars->val.integer) - values[count];
	    values[count] = *(vars->val.integer);
	    sprint_objid(buf, vars->name, vars->name_length);
	    for(cp = buf; *cp; cp++)
	      ;
	    while(cp >= buf){
	      if (isalpha(*cp))
		break;
	      cp--;
	    }
	    while(cp >= buf){
	      if (*cp == '.')
		break;
	      cp--;
	    }
	    cp++;
	    if (cp < buf)
	      cp = buf;
	    gettimeofday(&tv, (struct timezone *)0);
	    bcopy(localtime(&tv.tv_sec), &tm, sizeof(tm));
	    sprintf(timestring, "%d:%02d:%02d %d/%d", tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_mon+1, tm.tm_mday);
	    if (timestamp)
	      sprintf(label, "[%s] %s", timestring, cp);
	    else
	      sprintf(label, "%s", cp);
	    if (deltat){
	      if (last_time != 0){
		if (fileout){
		  sprintf(outstr, "%s /sec: %.2f", label, ((float)value * 100) / delta_time);
		  log(cp, outstr);
	        } else {
		  printf("%s /sec: %.2f\n", label, ((float)value * 100) / delta_time);
		  fflush(stdout);
		}
	      }
	    } else {
	      if (fileout){
		sprintf(outstr, "%s: %u", label, value);
		log(cp, outstr);
	      } else {
		printf("%s: %u\n", label, value);
		fflush(stdout);
	      }
	    }
	    vars = vars->next_variable;
	  }
	} else {
	  printf("Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
	  if (response->errstat == SNMP_ERR_NOSUCHNAME){
	    printf("This name doesn't exist: ");
	    for(count = 1, vars = response->variables; vars && count != response->errindex;
		vars = vars->next_variable, count++)
	      ;
	    if (vars)
	      print_objid(vars->name, vars->name_length);
	    printf("\n");
	  }
	  exit(1);
	  if ((pdu = snmp_fix_pdu(response, GET_REQ_MSG)) != NULL)
	    goto retry;
	}
	
      } else if (status == STAT_TIMEOUT){
	printf("No Response from %s\n", gateway);
      } else {    /* status == STAT_ERROR */
	printf("An error occurred, Quitting\n");
	break;
      }
      
      if (response)
	snmp_free_pdu(response);
      last_time = this_time;
      sleep(period);
    }
    snmp_close(ss);
    exit(0);
}

