#
# twparser.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = twparser
TYPE = LIBRARY

ADD_OBJS = 
ADD_SRCS =

DSP_OBJS = genreparseinfo.o parserhelper.o parserobjects.o policyparser.o stdtwparser.o twparser.o twparsererrors.o twparserstrings.o yylex.o yyparse.o

DSP_SRCS = $(patsubst %.o, %.cpp, $(DSP_OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)
SRCS = $(DSP_SRCS) $(ADD_SRCS)

include ../make_include/common_rules.mak