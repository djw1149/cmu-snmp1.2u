#! /bin/sh

#if test $# = 3 -a -f $1 -a -f $2 -a -f $3
if test $# = 3
then
	:
else
	echo usage: $0 TESTDIR TESTHOST TESTCOMM 1>&2
	exit
fi

TESTDIR=$1; export TESTDIR
TESTHOST=$2; export TESTHOST
TESTCOMM=$3; export TESTCOMM

echo Testing host $TESTHOST with community $TESTCOMM using executables
echo in $TESTDIR
set MIBFILE=$cwd/mib.txt; export MIBFILE

echo
echo TESTING $TESTDIR/snmpget $TESTHOST $TESTCOMM system.sysuptime.0
$TESTDIR/snmpget $TESTHOST $TESTCOMM system.sysuptime.0
echo Returned status is $?
echo
echo TESTING $TESTDIR/snmpgetnext $TESTHOST $TESTCOMM system.sysuptime.0
$TESTDIR/snmpgetnext $TESTHOST $TESTCOMM system.sysuptime.0
echo Returned status is $?
echo
echo TESTING $TESTDIR/snmpwalk $TESTHOST $TESTCOMM system
$TESTDIR/snmpwalk $TESTHOST $TESTCOMM system
echo Returned status is $?
echo
echo TESTING $TESTDIR/snmpwalk_asy $TESTHOST $TESTCOMM system
$TESTDIR/snmpwalk_asy $TESTHOST $TESTCOMM system
echo Returned status is $?
echo
echo TESTING $TESTDIR/snmptrap $TESTHOST $TESTCOMM 2 0
$TESTDIR/snmptrap $TESTHOST $TESTCOMM 2 0 <<DONE
interfaces.iftable.ifentry.ifindex.3
i
3

DONE
echo Returned status is $?
echo
echo TESTING $TESTDIR/snmptest $TESTHOST $TESTCOMM
$TESTDIR/snmptest $TESTHOST $TESTCOMM  <<DONE
system.sysuptime.0
DONE
echo Returned status is $?
echo
echo TESTING $TESTDIR/snmpstatus $TESTHOST $TESTCOMM
$TESTDIR/snmpstatus $TESTHOST $TESTCOMM
echo Returned status is $?
echo
echo TESTING $TESTDIR/snmproute $TESTHOST -c $TESTCOMM -g 1.1.1.1 -n 0.0.0.0
$TESTDIR/snmproute $TESTHOST -c $TESTCOMM -g 1.1.1.1 -n 0.0.0.0
echo Returned status is $?
echo
echo TESTING $TESTDIR/snmptranslate -D -n 2.1
$TESTDIR/snmptranslate -D -n 2.1
echo Returned status is $?



