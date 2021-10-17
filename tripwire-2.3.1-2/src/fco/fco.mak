#
# fco.mak
# See common_rules.mak for comments

include ../make_include/$(SYSPRE).inc

EXECUTABLE = fco
TYPE = LIBRARY

ADD_OBJS = 
ADD_SRCS =

DSP_OBJS = fco.o fcocompare.o fcodatasourceiter.o fcodatasourceiterimpl.o fcoerrors.o fconame.o fconametbl.o fcopropimpl.o fcopropvector.o fcosetimpl.o fcospec.o fcospecattr.o fcospechelper.o fcospecimpl.o fcospeclist.o fcospecutil.o fcostrings.o fcoundefprop.o genreinfo.o genrespeclist.o genreswitcher.o signature.o stdfco.o twfactory.o

DSP_SRCS = $(patsubst %.o, %.cpp, $(DSP_OBJS))  # i.e. blockfile.cpp

OBJS = $(DSP_OBJS) $(ADD_OBJS)

SRCS = $(ADD_SRCS) $(DSP_SRCS)

include ../make_include/common_rules.mak

