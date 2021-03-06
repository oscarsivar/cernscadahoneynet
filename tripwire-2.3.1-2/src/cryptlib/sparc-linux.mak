###############################################################################
# crypto++ library makefile
# "sparc-linux.mak"
#
# Use the targets 'debug' and 'release' to build this library.
# Be sure to 'make clean' when switching between debug and release modes.
#
#
# include a null char so VSS treats this as a binary file --> " #"
#

# -----------------------------------------------------------------
# ----------------- BEGIN CONFIGURABLE DEFINES --------------------

# ---------------------------
# --- Makefile --------------
# ---------------------------
# Change this if the name of this makefile changes, i.e. when porting

MAKEFILE = sparc-linux.mak

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
LINUX_X86 = -D_UNIX -D_LINUX -D_GCC

# Set platform to one of the above definitions
PLATFORM = $(LINUX_X86)
# TODO:  remove this spurious X86 reference
# TODO:  re-think the multi-platform approach for crypto++

DEBUG_FLAGS = -g -D_DEBUG
NDEBUG_FLAGS = -DNDEBUG
OFLAGS =  
MAKE_FLAGS = -M

# Note: D_FLAGS will be set in the "debug" or "release" target
D_FLAGS = !!!ERROR!!!

# ----------------------
# --- Compiler flags ---
# ----------------------

# The crypto++ web page says that 3.2 builds properly with gcc 2.95.2 (without any STL help), so
# linking with STLport here is probably unnecessary.  We haven't tested it though, so
# we'll leave it the way it is for now.
CXXFLAGS = $(PLATFORM) $(D_FLAGS) -w -I../STLport-4.0b5/stlport
LDFLAGS = -L../STLport-4.0b5/lib -lstlport_gcc


# ----------------- END OF CONFIGURABLE DEFINES --------------------
# ------------------------------------------------------------------


SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)
TESTOBJS = test.o bench.o validat1.o validat2.o validat3.o
LIBOBJS = $(filter-out $(TESTOBJS), $(OBJS))

###############################################################################
# Debug/Release targets
#
# Recusively call make defining the approprite $(D_FLAGS) var

debug:
	gmake -f $(MAKEFILE) cryptest_d "D_FLAGS=$(DEBUG_FLAGS)"

release:
	gmake -f $(MAKEFILE) cryptest "D_FLAGS=$(NDEBUG_FLAGS)"

 
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
	$(CXX) -o $@ $(NDEBUG_FLAGS) $(TESTOBJS) cryptlib.a $(LDFLAGS) -lm

cryptest_d: $(TESTOBJS) cryptlib_d.a
	$(CXX) -o $@ $(DEBUG_FLAGS) $(TESTOBJS) cryptlib_d.a $(LDFLAGS) -lm

###############################################################################
# other makes

all: cryptlib.a cryptest 
 
clean:
	- rm -f $(OBJS) 
	- rm -f crypto++.mak.dep

clobber: clean
	- rm -f cryptlib.a cryptlib_d.a
	- rm -f cryptest cryptest_d
 
.SUFFIXES: .cpp
 
.cpp.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(PLATFORM) $(DEBUG) -c $<

###############################################################################
# make depends

depend: crypto++.mak.dep

crypto++.mak.dep: $(SRCS)
	${CC} ${MAKE_FLAGS} ${PLATFORM} ${NDEBUG_FLAGS} *.cpp > crypto++.mak.dep

# Do not Delete

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),clobber)

include crypto++.mak.dep

endif
endif

# Do not Delete