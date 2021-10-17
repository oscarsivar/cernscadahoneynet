#
# tw.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = tw
TYPE = LIBRARY

ADD_OBJS = 
ADD_SRCS =

DSP_OBJS = configfile.o dbdatasource.o dbdebug.o dbexplore.o fcodatabasefile.o fcodatabaseutil.o fcoreport.o fcoreportutil.o filemanipulator.o headerinfo.o policyfile.o stdtw.o systeminfo.o textdbviewer.o textreportviewer.o tw.o twerrors.o twinit.o twstrings.o twutil.o

DSP_SRCS = $(patsubst %.o, %.cpp, $(OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)
SRCS = $(DSP_SRCS) $(ADD_SRCS)

include ../make_include/common_rules.mak
