CC = gcc
RM = rm
TARGET = msender mlistener pim_sender pim_listener udpserver udpclient msender6 mlistener6 syn_flood mdaemon nfsu2relay rcon snmpdos icqflood icqsnoop icqspoof getIPAddress rawtcp rawudp serverprog
SCRIPTS = msource.sh mgroup.sh mpim_rp.sh mpim_source.sh downalias.sh
DOCS = README
VERSION = 0.4

CFLAGS = -Wall

all:
	for i in $(TARGET); \
	do \
		$(CC) -o "$$i" "$$i".c $(CFLAGS); \
	done;

everything: $(TARGET)

msender:
	${CC} ${CFLAGS} msender.c -o msender

mlistener:
	${CC} ${CFLAGS} mlistener.c -o mlistener

pim_sender:
	${CC} ${CFLAGS} pim_sender.c -o pim_sender

pim_listener:
	${CC} ${CFLAGS} pim_listener.c -o pim_listener

udpserver:
	${CC} ${CFLAGS} udpserver.c -o udpserver

udpclient:
	${CC} ${CFLAGS} udpclient.c -o udpclient

msender6:
	${CC} ${CFLAGS} msender6.c -o msender6

mlistener6:
	${CC} ${CFLAGS} mlistener6.c -o mlistener6
	
syn_flood:
	${CC} ${CFLAGS} syn_flood.c -o syn_flood
	
mdaemon:
	${CC} ${CFLAGS} mdaemon.c -o mdaemon
	
nfsu2relay:
	${CC} ${CFLAGS} nfsu2relay.c -o nfsu2relay
	
rcon:
	${CC} ${CFLAGS} rcon.c -o rcon
	
snmpdos:
	${CC} ${CFLAGS} snmpdos.c -o snmpdos
	
icqflood:
	${CC} ${CFLAGS} icqflood.c -o icqflood
	
icqflood:
	${CC} ${CFLAGS} icqsnoop.c -o icqsnoop
	
icqflood:
	${CC} ${CFLAGS} icqspoof.c -o icqspoof

getIPAddress:
	${CC} ${CFLAGS} getIPAddress.c -o getIPAddress

tarball:
	tar czf msuite_${VERSION}.tgz ${TARGET} ${SCRIPTS} ${DOCS}

7zpkg:
	7za a msuite_${VERSION}.7z ${SCRIPTS} ${DOCS}
	for i in $(TARGET); \
	do \
		7za u msuite_${VERSION}.7z "$$i".c; \
	done;
	

clean:
	${RM} -f *.o *~
	#${RM} -f ${TARGET}
	${RM} -f $$(file `find .` | grep "bit executable" | awk '{print $$1}' | sed 's/\.*\://')
	#filenames=$$(file `find .` | grep "bit executable" | awk '{print $$1}' | sed 's/\.*\://')
	#echo $$filenames
	#for i in $$filenames; do rm -f $$i ; done;
