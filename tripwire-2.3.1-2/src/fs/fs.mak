#
# fs.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = fs
TYPE = LIBRARY

ADD_OBJS = 
ADD_SRCS =

DSP_OBJS = fs.o fsdatasourceiter.o fserrors.o fsfactory.o fsnametranslator.o fsobject.o fsparserutil.o fspropcalc.o fspropdisplayer.o fspropset.o fsstrings.o fsvisitor.o stdfs.o

DSP_SRCS = $(patsubst %.o, %.cpp, $(DSP_OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)

SRCS = $(DSP_SRCS) $(ADD_SRCS)


include ../make_include/common_rules.mak

