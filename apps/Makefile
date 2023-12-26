#
# Makefile for SNMP applications
#
TARG=	snmpget snmpgetnext snmpwalk snmpwalk_asy snmpstatus snmptest \
	snmptrap snmptrapd snmpd snmptranslate snmproute snmpdelta
LIBS=	../lib/libsnmp.a
CFLAGS=-g -I../snmplib -DBSD4_3

all: $(TARG)

snmpget:    snmpget.o ${LIBS}
	${CC} -o $@ snmpget.o ${LIBS}

snmpgetnext:    snmpgetnext.o ${LIBS}
	${CC} -o $@ snmpgetnext.o ${LIBS}

snmpwalk:    snmpwalk.o ${LIBS}
	${CC} -o $@ snmpwalk.o ${LIBS}

snmpwalk_asy:    snmpwalk_asy.o ${LIBS}
	${CC} -o $@ snmpwalk_asy.o ${LIBS}

snmpstatus:    snmpstatus.o ${LIBS}
	${CC} -o $@ snmpstatus.o ${LIBS}

snmproute:    snmproute.o ${LIBS}
	${CC} -o $@ snmproute.o ${LIBS}

snmptest:    snmptest.o ${LIBS}
	${CC} -o $@ snmptest.o ${LIBS}

snmptrap:    snmptrap.o ${LIBS}
	${CC} -o $@ snmptrap.o ${LIBS}

snmptrapd:    snmptrapd.o ${LIBS}
	${CC} -o $@ snmptrapd.o ${LIBS}

snmpdelta:    snmpdelta.o ${LIBS}
	${CC} -o $@ snmpdelta.o ${LIBS}

snmptranslate:    snmptranslate.o ${LIBS}
	${CC} -o $@ snmptranslate.o ${LIBS}

snmpd:	snmpd.o kernel.o ${LIBS} snmp_agent.o snmp_vars.o snmp_var_route.o
	${CC} -o $@ snmpd.o kernel.o snmp_agent.o snmp_vars.o \
		snmp_var_route.o ${LIBS}

clean:
	rm -f *.o ${TARG}

install:
	cp ${TARG} ../bin

