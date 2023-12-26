#
# Copyright (c) 1987 Regents of the University of California.
# All rights reserved.
#
# Redistribution and use in source and binary forms are permitted
# provided that the above copyright notice and this paragraph are
# duplicated in all such forms and that any documentation,
# advertising materials, and other materials related to such
# distribution and use acknowledge that the software was developed
# by the University of California, Berkeley.  The name of the
# University may not be used to endorse or promote products derived
# from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
# WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#
#	@(#)Makefile	5.10 (Berkeley) 9/20/88
#
#
# $Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/snmpnetstat/Makefile,v 1.4 1996/11/14 15:39:40 tpt2 Exp $
#
# Makefile for SNMP applications
#

#################################################
# This sets LIBS, CFLAGS, IFLAGS, SRC_TO_OBJ, etc
#################################################
include defs.m

IFLAGS= -I${TI}/cmusnmp 
#CFLAGS=-DBSD4_3 ${CFLAGS}
#LINTFLAGS = -DBSD4_3  -b -u ${LINTFLAGS}
LINTFLAGS =  -b -u ${LINTFLAGS}

LIBS =  ${T}/lib/libcmusnmp.a

TEST   = /dev/null

include dev.m

SOURCE= inet.c if.c main.c route.c 
PROG = snmpnetstat
include prog.m

MANSRC = snmpnetstat.1
include man.m
