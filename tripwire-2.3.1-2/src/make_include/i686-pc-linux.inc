#
# i686-pc-linux.inc
#
# Makefile definitions for Linux Intel, Redhat executables and libraries
# Modified to use gcc 2.95.2  and STLport 4.0 beta 8
#
# include a null char so VSS treats this as a binary file --> " #"

# 
# Libraries, such as db.a, will end up in something ike ../lib/ix86-pc-linux/
LIBDIR=../../lib
LIBPRE=$(LIBDIR)/$(SYSPRE)

BINDIR=../../bin
BINPRE=$(BINDIR)/$(SYSPRE)


#
# General variable definitions
#

GMAKE = /usr/bin/gmake
CC = g++
CXX = $(CC)
AR = ar
SYSDEF=-D_REDHAT -D_IX86 -D_GCC
STLPORT=../STLport-4.0

#
# release flags
#

CXXFLAGS_R = -I.. -I$(STLPORT)/stlport -ftemplate-depth-32
DEFINES_R = -DNDEBUG $(SYSDEF)
LINKFLAGS_R = -static
LIBRARYFLAGS_R = -L../../lib/$(SYSPRE)_r -lm -lstlport_gcc
ARFLAGS_R = crv

#
# debug flags
#

CXXFLAGS_D = -I.. -I$(STLPORT)/stlport -g -ftemplate-depth-32
DEFINES_D = -D_DEBUG -D_DEBUG_DB $(SYSDEF)
LINKFLAGS_D = -static
LIBRARYFLAGS_D = -L../../lib/$(SYSPRE)_d -lm -lstlport_gcc
ARFLAGS_D = crv

#
# depend flags
#

DEPEND_FLAGS = -M -w -I.. -I$(STLPORT)/stlport -DNDEBUG $(SYSDEF)
