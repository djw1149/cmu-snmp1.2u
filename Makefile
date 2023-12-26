
all:	makeall

install:
	cd apps; make install
	cd apps/snmpnetstat; make install

makeall:
	cd snmplib; make all install
	cd apps; make
	cd apps/snmpnetstat; make

clean:
	cd snmplib; make clean
	cd apps; make clean
	cd apps/snmpnetstat; make clean


