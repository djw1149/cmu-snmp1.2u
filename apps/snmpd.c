#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/snmpd.c,v 1.2 1992/07/29 18:16:43 djw Exp $";
#endif

/*
 * snmpd.c - send snmp GET requests to a network entity.
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
#include <sys/socket.h>
#include <errno.h>

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"

extern int  errno;
int	snmp_dump_packet = 0;

main(argc, argv)
    int	    argc;
    char    *argv[];
{
    int	arg;
    int sd;
    struct sockaddr_in	me;


    /*
     * usage: snmpd
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
    }
    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	return 1;
    }
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(SNMP_PORT);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	return 2;
    }
    init_snmp();
    receive(sd);
    return 0;
}

receive(sd)
    int sd;
{
    int numfds;
    fd_set fdset;
    int count;

    while(1){
	numfds = 0;
	FD_ZERO(&fdset);
	numfds = sd + 1;
	FD_SET(sd, &fdset);
	count = select(numfds, &fdset, 0, 0, 0);
	if (count > 0){
	    if(FD_ISSET(sd, &fdset))
		snmp_read_agent(sd);
	} else switch(count){
	    case 0:
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

snmp_read_agent(sd)
    int sd;
{
    struct sockaddr_in	from;
    int length, out_length, fromlength;
    u_char  packet[1500], outpacket[1500];

    fromlength = sizeof from;
    length = recvfrom(sd, packet, 1500, 0, (struct sockaddr *)&from, &fromlength);
    if (length == -1)
	perror("recvfrom");
    if (snmp_dump_packet){
	int count;

	printf("received %d bytes from %s:\n", length, inet_ntoa(from.sin_addr));
	for(count = 0; count < length; count++){
	    printf("%02X ", packet[count]);
	    if ((count % 16) == 15)
		printf("\n");
	}
	printf("\n\n");
    }
    out_length = 1500;
    if (snmp_agent_parse(packet, length, outpacket, &out_length, from.sin_addr.s_addr)){
	if (snmp_dump_packet){
	    int count;

	    printf("sent %d bytes to %s:\n", out_length, inet_ntoa(from.sin_addr));
	    for(count = 0; count < out_length; count++){
		printf("%02X ", outpacket[count]);
		if ((count % 16) == 15)
		    printf("\n");
	    }
	    printf("\n\n");
	}
	if (sendto(sd, (char *)outpacket, out_length, 0, (struct sockaddr *)&from,
	    sizeof(from)) < 0){
		perror("sendto");
		return 0;
	}

    }
    return 1;
}

