OS := $(shell uname -s)
CC = gcc
CXX = g++
RM = rm
MAKE = make

ifeq ($(OS),Darwin)
LIB_NVRAM= nvram-1.0-1.0.1
CFLAGS = -I/opt/local/include -L/opt/local/lib -lpth
CPPFLAGS = $(CFLAGS)
else
ifeq ($(OS),Linux)
LIB_NVRAM= nvram-1.0
CFLAGS = -lpthread -lrt
CPPFLAGS = $(CFLAGS)
endif
endif

SUBDIR := gethostinfo

SOURCE := $(wildcard *.c) $(wildcard *.cc) $(wildcard *.cxx) $(wildcard *.cpp)

OPTIMIZE = -g
WARNINGS = -W -Wall -pedantic -Wno-long-long -Wextra -Wdeclaration-after-statement -Wendif-labels -Wconversion -Wcast-qual -Wwrite-strings
INCLUDE  = -I.
CFLAGS   += $(WARNINGS) $(OPTIMIZE) $(INCLUDE)

CPPFLAGS = -fno-stack-protector -Wall -I$(HOME)/include -I/usr/local/include -L$(HOME)/lib -L/usr/local/lib -l$(LIB_NVRAM) -lssl -lcrypto $(CFLAGS)
CFLAGS += -Wall -I$(HOME)/include -I/usr/local/include -L$(HOME)/lib -L/usr/local/lib -l$(LIB_NVRAM) -lssl -lcrypto -lpcap

TARGET = msender mlistener pim_sender pim_listener udpserver udpclient msender6 mlistener6 syn_flood mdaemon nfsu2relay rcon snmpdos icqflood icqsnoop icqspoof getIPAddress rawtcp rawudp serverprog
SCRIPTS = msource.sh mgroup.sh mpim_rp.sh mpim_source.sh downalias.sh
DOCS = README
VERSION = 0.5

all:
	@TARGETS=""; for i in $(SOURCE); do TARGETS+=$$(echo $$i | awk -F"." '{ printf $$1}'); TARGETS+=" "; done; \
	for i in $$TARGETS; \
	do \
		if [ -e "$$i".c ]; then $(CC) -o "$$i" "$$i".c $(CFLAGS); fi; \
		if [ -e "$$i".cc ]; then $(CXX) -o "$$i" "$$i".cc $(CPPFLAGS); fi; \
		if [ -e "$$i".cpp ]; then $(CXX) -o "$$i" "$$i".cpp $(CPPFLAGS); fi; \
		#$(MAKE) $(CFLAGS) $$i; \
	done;
	for dir in ${SUBDIR}; do \
		${MAKE} -C $$dir; \
	done
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
	${RM} -fr *.dSYM
ifeq ($(strip $(OS)),Darwin)
	#${RM} -f $$(file `find .` | grep "bit executable" | awk '{print $$1}' | sed 's/\.*\://')
	${RM} -f $$(file `find .` | grep "Mach-O ...* executable" | awk '{print $$1}' | sed 's/\.*\://')
else ifeq ($(strip $(OS)),Linux)
	${RM} -f $$(file `find .` | grep "bit ...* executable" | awk '{print $$1}' | sed 's/\.*\://')
endif
	for dir in ${SUBDIR}; do \
		${MAKE} -C $$dir clean; \
	done
