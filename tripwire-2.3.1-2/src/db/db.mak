#
# db.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = db
TYPE = LIBRARY

ADD_OBJS = 
ADD_SRCS =

DSP_OBJS = blockfile.o blockrecordarray.o blockrecordfile.o db.o hierdatabase.o hierdbpath.o stddb.o

DSP_SRCS = $(patsubst %.o, %.cpp, $(DSP_OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)

SRCS = $(ADD_OBJS) $(DSP_SRCS)

include ../make_include/common_rules.mak

