#
# twcrypto.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = twcrypto
TYPE = LIBRARY

ADD_OBJS = 
ADD_SRCS =

DSP_OBJS = bytequeue.o crypto.o cryptoarchive.o keyfile.o stdtwcrypto.o twcrypto.o twcryptoerrors.o

DSP_SRCS = $(patsubst %.o, %.cpp, $(DSP_OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)
SRCS = $(DSP_SRCS) $(ADD_SRCS)

include ../make_include/common_rules.mak
