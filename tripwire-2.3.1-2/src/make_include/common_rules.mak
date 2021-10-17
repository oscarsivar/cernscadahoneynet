#
# common_rules.mak
#
# Each EXECUTABLE is of TYPE LIBRARY, such as core, or of TYPE BINARY, such as twadmin
# The source files for EXECUTABLE are in code/EXECUTABLE, which also contains EXECUTABLE.mak.
# 
# EXECUTABLE.mak includes SYSPRE.inc, where SYSPRE must be specified when EXECUTABLE.mak is
# invoked.  SYSPRE indicates the platform architecture, e.g. SYSPRE=i686-pc-linux.  SYSPRE.inc
# contains platform-specific target-directories, compiler names, and flags.
# EXECUTABLE.mak defines the name of EXECUTABLE and its TYPE.  It specifies the names of all the 
# source (SRCS) and object (OBJS) files that EXECUTABLE needs.  It specifies which can be compiled
# with the generic rule contained in this file (DSP_SRCS), and which need individually defined rules
# (ADD_SRCS).  IF there are any ADD_SRCS, their rules will be in EXECUTABLE.mak as well.
#
# EXECUTABLE.mak then includes this file, common_rules.mak, which specifies how to build release and
# debug targets of EXECUTABLE, as well as how to compile DSP_SRCS into DSP_OBJS 

STRIP=strip
#STRIP=echo		# uncomment this to keep the debug files safe

##### TARGETS #####
#

default:
	@echo Usage:  make -f (this file).mak [release|debug] "SYSPRE=[i686-pc-linux|...]"

# Clear out suffix rules, to be safe
.SUFFIXES:

# Just in case there's a file with these names
.PHONY: doall release debug clean clobber


##### Dependency File #####
# Only build this if not cleaning or clobbering.
# There is one .dep file for each system type, since the prefix added by the perl script changes with
# the type of system.  Example:  db.i686-pc-linux.dep
# The perl script adds a directory to the object files, i.e. blockfile.o -> 
# db_i686-pc-linux_d/blockfile.o    db_i686-pc-linux_r/blockfile.o
# (The object files are re-directed into sub-directories in order to keep debug and release object
# files separate.)

$(EXECUTABLE).$(SYSPRE).dep:
	$(CC) $(DEPEND_FLAGS) $(SRCS) > $(EXECUTABLE).$(SYSPRE).dep
	../dep_addprefix.pl $(EXECUTABLE).$(SYSPRE).dep $(EXECUTABLE)_$(SYSPRE)_d $(EXECUTABLE)_$(SYSPRE)_r

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),clobber)

include $(EXECUTABLE).$(SYSPRE).dep

endif
endif


##### targets for libraries #####

ifeq ($(TYPE),LIBRARY)

# Release and Debug targets
# These call make doall recursively with compile flags set properly

release: 
	$(GMAKE) -f $(EXECUTABLE).mak doall "CXXFLAGS=$(CXXFLAGS_R)" "DEFINES=$(DEFINES_R)" "LINKFLAGS=$(LINKFLAGS_R)" "ARFLAGS=$(ARFLAGS_R)" "SYSPRE=$(SYSPRE)" "BUILDTYPE=r"

debug:
	$(GMAKE) -f $(EXECUTABLE).mak doall "CXXFLAGS=$(CXXFLAGS_D)" "DEFINES=$(DEFINES_D)" "LINKFLAGS=$(LINKFLAGS_D)" "ARFLAGS=$(ARFLAGS_D)" "SYSPRE=$(SYSPRE)" "BUILDTYPE=d"


# 'Make doall' builds the directory structure
# i.e. db.a_i686-pc-linux_d/ for the objects 
# and ../lib/i686-pc-linux_d for the library
# Then 'make doall' builds the library by calling make ../lib/i686-pc-linux_d/db.a

doall:
	test -d $(EXECUTABLE)_$(SYSPRE)_$(BUILDTYPE) || mkdir $(EXECUTABLE)_$(SYSPRE)_$(BUILDTYPE)
	test -d $(LIBDIR) || mkdir $(LIBDIR)
	test -d $(LIBPRE)_$(BUILDTYPE) || mkdir $(LIBPRE)_$(BUILDTYPE)
	$(GMAKE) -f $(EXECUTABLE).mak $(LIBPRE)_$(BUILDTYPE)/$(EXECUTABLE).a "OBJDIR=$(EXECUTABLE)_$(SYSPRE)_$(BUILDTYPE)"
endif


##### targets for binaries #####

ifeq ($(TYPE),BINARY)

# These libraries MUST be in this order or there will be link errors!
LIBRARIES_BASE = tw.a fs.a twparser.a fco.a db.a util.a twcrypto.a core.a cryptlib.a 
LIBRARIES_R = ${addprefix $(LIBPRE)_r/, $(LIBRARIES_BASE)}
LIBRARIES_D = ${addprefix $(LIBPRE)_d/, $(LIBRARIES_BASE)}

release: 
	$(GMAKE) -f $(EXECUTABLE).mak doall "CXXFLAGS=$(CXXFLAGS_R)" "DEFINES=$(DEFINES_R)" "LINKFLAGS=$(LINKFLAGS_R)" "LIBRARIES=$(LIBRARIES_R)" "LIBRARYFLAGS=$(LIBRARYFLAGS_R)" "SYSPRE=$(SYSPRE)" "BUILDTYPE=r"
	$(STRIP) $(BINPRE)_r/$(EXECUTABLE)

debug:
	$(GMAKE) -f $(EXECUTABLE).mak doall "CXXFLAGS=$(CXXFLAGS_D)" "DEFINES=$(DEFINES_D)" "LINKFLAGS=$(LINKFLAGS_D)" "LIBRARIES=$(LIBRARIES_D)" "LIBRARYFLAGS=$(LIBRARYFLAGS_D)" "SYSPRE=$(SYSPRE)" "BUILDTYPE=d"

doall:
	test -d $(EXECUTABLE)_$(SYSPRE)_$(BUILDTYPE) || mkdir $(EXECUTABLE)_$(SYSPRE)_$(BUILDTYPE)
	test -d $(BINDIR) || mkdir $(BINDIR)
	test -d $(BINPRE)_$(BUILDTYPE) || mkdir $(BINPRE)_$(BUILDTYPE)
	$(GMAKE) -f $(EXECUTABLE).mak $(BINPRE)_$(BUILDTYPE)/$(EXECUTABLE) "OBJDIR=$(EXECUTABLE)_$(SYSPRE)_$(BUILDTYPE)"
endif


##### targets for both libraries and binaries #####

# Here the library/binary is explicitly built from the object files
# For example, 
# ../lib/i686-pc-linux_d/db.a: db_i686-pc-linux_d/blockfile.o ...
# or
# ../bin/i686-pc-linux_r/tripwire: tripwire_i686-pc-linux_r/tripwire.o ...  ../../lib/i686-pc-linux_r/core.a ...
# Note that $(CXXFLAGS), etc. are not passed to the compiler because we're really only linking

$(LIBPRE)_$(BUILDTYPE)/$(EXECUTABLE).a: ${addprefix $(OBJDIR)/, $(OBJS)}
	- rm -f $(LIBPRE)_$(BUILDTYPE)/$(EXECUTABLE).a
	$(AR) $(ARFLAGS) $(LIBPRE)_$(BUILDTYPE)/$(EXECUTABLE).a $(addprefix $(OBJDIR)/,$(OBJS))

$(BINPRE)_$(BUILDTYPE)/$(EXECUTABLE): ${addprefix $(OBJDIR)/, $(OBJS)} $(LIBRARIES)
	$(CXX) -o $(BINPRE)_$(BUILDTYPE)/$(EXECUTABLE) $(addprefix $(OBJDIR)/,$(OBJS)) $(LINKFLAGS) $(LIBRARIES) $(LIBRARYFLAGS)


# Here the object files are compiled
# For example,
# db_i686-pc-linux_d/blockfile.o :
#	g++ -o db_i686-pc-linux_d/blockfile.o ... -c blockfile.cpp
# The dependency information is not listed here because it is in in $(EXECUTABLE).$(SYSPRE).dep

$(addprefix $(OBJDIR)/,$(DSP_OBJS)) :
	$(CXX) -o $@ $(CXXFLAGS) $(DEFINES) -c $(patsubst $(OBJDIR)/%.o, %.cpp, $@)


##### clean and clobber #####
clean:
	- rm -rf $(EXECUTABLE)_$(SYSPRE)_d
	- rm -rf $(EXECUTABLE)_$(SYSPRE)_r

# Slight difference in clobber depending on executable type

ifeq ($(TYPE),LIBRARY)
# remove the libraries
clobber: clean
	- rm -f $(LIBPRE)_d/$(EXECUTABLE).a
	- rm -f $(LIBPRE)_r/$(EXECUTABLE).a
endif

ifeq ($(TYPE),BINARY)
# remove the binaries
clobber: clean
	- rm -f $(BINPRE)_d/$(EXECUTABLE)
	- rm -f $(BINPRE)_r/$(EXECUTABLE)
endif
