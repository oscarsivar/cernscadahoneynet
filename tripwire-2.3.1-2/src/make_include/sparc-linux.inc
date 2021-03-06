#
# i686-pc-linux.inc
#
# Makefile definitions for Linux Intel, Redhat executables and libraries
# Modified to use gcc 2.95.2  and STLport 4.0 beta 5
#
# include a null char so VSS treats this as a binary file --> " #"


#
# General variable definitions
#

GMAKE = /usr/bin/gmake
CC = g++
CXX = $(CC)
AR = ar
SYSDEF=-D_REDHAT -D_SPARC -D_GCC
STLPORT=../STLport-4.0b5

#
# release flags
#

CXXFLAGS_R = -I.. -I$(STLPORT)/stlport
DEFINES_R = -DNDEBUG $(SYSDEF)
LINKFLAGS_R = -static
LIBRARYFLAGS_R = -L$(STLPORT)/lib -lm -lstlport_gcc -lsocket -lnsl
ARFLAGS_R = crv

#
# debug flags
#

CXXFLAGS_D = -I.. -I$(STLPORT)/stlport -g
DEFINES_D = -D_DEBUG -D_DEBUG_DB $(SYSDEF)
LINKFLAGS_D = -static
LIBRARYFLAGS_D = -L$(STLPORT)/lib -lm -lstlport_gcc -lsocket -lnsl -lw

#
# depend flags
#

DEPEND_FLAGS = -M -w -I.. -I$(STLPORT)/stlport -DNDEBUG $(SYSDEF)
