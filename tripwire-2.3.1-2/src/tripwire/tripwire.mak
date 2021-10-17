#
# tripwire.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = tripwire
TYPE = BINARY

ADD_OBJS = 
ADD_SRCS = 

DSP_OBJS = generatedb.o integritycheck.o mailmessage.o pipedmailmessage.o policyupdate.o smtpmailmessage.o stdtripwire.o syslog.o tripwire.o tripwireerrors.o tripwiremain.o tripwirestrings.o tripwireutil.o twcmdline.o twcmdlineutil.o updatedb.o

DSP_SRCS = $(patsubst %.o, %.cpp, $(DSP_OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)
SRCS = $(DSP_SRCS) $(ADD_SRCS)

include ../make_include/common_rules.mak