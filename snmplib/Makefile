#
# Makefile for snmplib
#
TARG=	libsnmp.a
CSRCS=	snmp_client.c mib.c parse.c snmp_api.c snmp.c snmp_auth.c asn1.c
OBJS=	snmp_client.o mib.o parse.o snmp_api.o snmp.o snmp_auth.o asn1.o
CFLAGS=-g -DBSD4_3 

all: $(TARG)

libsnmp.a:    ${OBJS}
	rm -f libsnmp.a
	ar rc libsnmp.a ${OBJS}
	ranlib libsnmp.a

install:	../lib/libsnmp.a

../lib/libsnmp.a:	libsnmp.a
	cp libsnmp.a ../lib
	ranlib ../lib/libsnmp.a


lint:
	lint -nhx $(CSRCS)

clean:
	rm -f ${OBJS} ${TARG}
	rm -f ../lib/${TARG}

## Dependencies:
asn1.o: asn1.c
asn1.o: ./asn1.h
mib.o: mib.c
mib.o: ./asn1.h
mib.o: ./snmp_impl.h
mib.o: ./snmp_api.h
mib.o: ./parse.h
parse.o: parse.c
parse.o: ./parse.h
snmp.o: snmp.c
snmp.o: ./asn1.h
snmp.o: ./snmp.h
snmp.o: ./snmp_impl.h
snmp.o: ./mib.h
snmp_api.o: snmp_api.c
snmp_api.o: ./asn1.h
snmp_api.o: ./snmp.h
snmp_api.o: ./snmp_impl.h
snmp_api.o: ./snmp_api.h
snmp_auth.o: snmp_auth.c
snmp_auth.o: ./asn1.h
snmp_auth.o: ./snmp.h
snmp_auth.o: ./snmp_impl.h
snmp_client.o: snmp_client.c
snmp_client.o: ./asn1.h
snmp_client.o: ./snmp.h
snmp_client.o: ./snmp_impl.h
snmp_client.o: ./snmp_api.h
snmp_client.o: ./snmp_client.h
