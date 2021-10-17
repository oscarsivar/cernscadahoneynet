#
# twadmin.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = twadmin
TYPE = BINARY

ADD_OBJS = 
ADD_SRCS = 

DSP_OBJS = keygeneration.o stdtwadmin.o twadmin.o twadmincl.o twadminerrors.o twadminmain.o twadminstrings.o
DSP_SRCS = $(patsubst %.o, %.cpp, $(DSP_OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)
SRCS = $(DSP_SRCS) $(ADD_SRCS)

include ../make_include/common_rules.mak