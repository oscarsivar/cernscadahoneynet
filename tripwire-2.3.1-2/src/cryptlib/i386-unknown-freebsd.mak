###############################################################################
# crypto++ library makefile
# "i386-unknown-freebsd.mak"
#
# Use the targets 'debug' and 'release' to build this library.
# Be sure to 'make clean' when switching between debug and release modes.
#
#
# include a null char so VSS treats this as a binary file --> " #"
#

# -----------------------------------------------------------------
# ----------------- BEGIN CONFIGURABLE DEFINES --------------------

# ---------------------------
# --- Makefile --------------
# ---------------------------
# Change this if the name of this makefile changes, i.e. when porting
SYSPRE = i386-unknwon-freebsd
MAKEFILE = $(SYSPRE).mak

# ---------------------------
# --- Program definitions ---
# ---------------------------
# 
CC = g++
CXX = $(CC)
AR = ar crv
RANLIB = ranlib

# ----------------------------
# --- Platform definitions ---
# ----------------------------
LINUX_X86 = -D_UNIX -D_LINUX -D_LITTLE_ENDIAN -D_GCC

# Set platform to one of the above definitions
PLATFORM = $(LINUX_X86)
 
DEBUG_FLAGS = -g -D_DEBUG
NDEBUG_FLAGS = -DNDEBUG
OFLAGS =  
MAKE_FLAGS = -M

# Note: D_FLAGS will be set in the "debug" or "release" target
D_FLAGS = !!!ERROR!!!
LD_FLAGS = !!!ERROR!!!

# ----------------------
# --- Compiler flags ---
# ----------------------

# The crypto++ web page says that 3.2 builds properly with gcc 2.95.2 (without any STL help), so
# linking with STLport here is probably unnecessary.  We haven't tested it though, so
# we'll leave it the way it is for now.
CXXFLAGS = $(PLATFORM) $(D_FLAGS) -w -I../STLport-4.0/stlport
DEBUG_LDFLAGS = -L../../lib/$(SYSPRE)_d -lstlport_gcc
NDEBUG_LDFLAGS = -L../../lib/$(SYSPRE)_r -lstlport_gcc

# ----------------- END OF CONFIGURABLE DEFINES --------------------
# ------------------------------------------------------------------


SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)
TESTOBJS = test.o bench.o validat1.o validat2.o validat3.o
LIBOBJS = $(filter-out $(TESTOBJS), $(OBJS))

###############################################################################
# Debug/Release targets
#
# Recusively call make defining the appropriate $(D_FLAGS) var

debug:
	gmake -f $(MAKEFILE) cryptlib_d.a "D_FLAGS=$(DEBUG_FLAGS)" "LDFLAGS=DEBUG_LDFLAGS"
#	gmake -f $(MAKEFILE) cryptest_d "D_FLAGS=$(DEBUG_FLAGS)" "LDFLAGS=DEBUG_LDFLAGS"

release: 
	gmake -f $(MAKEFILE) cryptlib.a "D_FLAGS=$(NDEBUG_FLAGS)" "LDFLAGS=NDEBUG_LDFLAGS"
#	gmake -f $(MAKEFILE) cryptest "D_FLAGS=$(NDEBUG_FLAGS)" "LDFLAGS=NDEBUG_LDFLAGS"

 
###############################################################################
# make cryptlib.a

cryptlib.a: $(LIBOBJS)
	- rm -f $@
	$(AR) $@ $(LIBOBJS)

cryptlib_d.a: $(LIBOBJS)
	- rm -f $@
	$(AR) $@ $(LIBOBJS)

###############################################################################
# make crypttest

cryptest: $(TESTOBJS) cryptlib.a
	$(CXX) -o $@ $(NDEBUG_FLAGS) $(TESTOBJS) cryptlib.a $(NDEBUG_LDFLAGS) -lm

cryptest_d: $(TESTOBJS) cryptlib_d.a
	$(CXX) -o $@ $(DEBUG_FLAGS) $(TESTOBJS) cryptlib_d.a $(DEBUG_LDFLAGS) -lm

###############################################################################
# other makes

all: cryptlib.a cryptest 
 
clean:
	- rm -f $(OBJS) 
	- rm -f crypto++.$(SYSPRE).dep

clobber: clean
	- rm -f cryptlib.a cryptlib_d.a
	- rm -f cryptest cryptest_d
 
.SUFFIXES: .cpp
 
.cpp.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(PLATFORM) $(DEBUG) -c $<

###############################################################################
# make depends

depend: crypto++.$(SYSPRE).dep

crypto++.$(SYSPRE).dep: $(SRCS)
	${CC} ${MAKE_FLAGS} ${PLATFORM} ${NDEBUG_FLAGS} *.cpp > crypto++.$(SYSPRE).dep

# Do not Delete

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),clobber)

include crypto++.$(SYSPRE).dep

endif
endif

# Do not Delete
