##############################################################################
# Tripwire Master Makefile
# 
# *** Configuration
#
# This makefile handles different platforms targets through the use of the 
# makefile variable "SYSPRE".	 To configure the make process for your specific
# platform edit the SYSPRE variable in the Configuration section below to match your
# setup.
#
# During the build process this makefile recursively calls gmake using this
# file (Makefile) or one of the subdirectory makefiles (e.g. core/core.mak) 
# as the makefile.  When it does this it passes the SYSPRE definition along
# by using the directive "SYSPRE=$(SYSPRE)".
#
# Comments that start with '#=' are echoed to the screen by the default target, help.
#= *** Build Commands 
#=
#= Please note that all Tripwire makefiles require GNU make (gmake) to build!
#=
#= To create release binaries and generate a log file:
#=
#=	  gmake release
#=
#= To create debug binaries and generate a log file:
#=
#=	  gmake debug
#=
#= There are four release or debug binaries.  They are:
#= twadmin tripwire twprint siggen
#=
#= To create individual release or debug binaries respectively:
#=
#=	  gmake twadmin_r
#=	  gmake twadmin_d
#=
#= To create individual release or debug libraries respectively:
#=
#=	  gmake core_r
#=	  gmake core_d
#=
#= The libraries are:
#= STLport cryptlib core db fco fs tw twcrypto twparser util
#= 
#= To erase object files, but not executable and lib files:
#=
#=	  gmake clean
#=
#= To erase all output files, including executable and library files 
#=	(except STLport libraries, see next directive):
#=
#=	  gmake clobber
#=
#= To clobber everything including the STLport libs (Note:  This will remove 
#= the bin directory, including any config or policy files contained therein.):
#=
#=	  gmake distclean
#=
##############################################################################


##############################################################################
# BEGIN: Configuration section



#-----------------------------------------------------------------------------
# SYSPRE makefile variable
#
# System prefix convention is to use a single character to designate the 
# operating system and a single character to designate the architecture.  
#
# Uncomment the appropriate SYSPRE definition below for your architecture.
# Note that if you uncomment more than one, gmake will use the last one.
#
# Prefix for various OS/Architectures:
#
# i686-pc-linux == Linux Intel x86
# sparc-linux == Linux Sparc (not fully implemented)
#

SYSPRE = i686-pc-linux
#SYSPRE = sparc-linux
#SYSPRE = i386-unknown-freebsd
#SYSPRE = i386-unknown-openbsd


#-----------------------------------------------------------------------------
# MAKEFILE
#
# Set this to the name of this file.  This is used when we recursively call
# gmake on this file.  We include this variable so that you can rename this
# file to Makefile.linux_intel or something similar.

MAKEFILE = Makefile
GMAKE = gmake

#-----------------------------------------------------------------------------
# STLPORT
#
# The directory of the STLport.  If this changes, it must be changed here,
# in $(SYSPRE).inc, and in cryptlib/$(SYSPRE).mak

STLPORT = STLport-4.0


# END: Configuration section
##############################################################################
# BEGIN: Variable definitions


LIBDIR=../lib
LIBPRE=$(LIBDIR)/$(SYSPRE)
# eg, ../lib/i686-pc-linux
BINDIR=../bin
BINPRE=$(BINDIR)/$(SYSPRE)


# Here are the four main executables, or twixes.  
#
binaries  = twprint twadmin siggen tripwire

# ('test' is a binary, but we don't want it automatically made when
# 'make debug' or 'make release' is invoked)

debugbinaries = $(patsubst %, %_d, $(binaries))     # e.g, twprint_d
releasebinaries = $(patsubst %, %_r, $(binaries))   # e.g, twprint_r


# These are the sub-projects, or libraries
# This is the only place where they are listed
# To add a new sub-project, append it here
# Also, it must live in a directory of the same name,
# and have a Makefile named <project>.mak
# The Makefile must have the targets:
# clean   clobber   debug   release

libraries = cryptlib core db fco fs tw twcrypto twparser util

debuglibraries = $(patsubst %, %_d, $(libraries))     # e.g, core_d
releaselibraries = $(patsubst %, %_r, $(libraries))   # e.g, core_r

# TODO:  modify STLport so that it can be included in libraries too.


# It's handy for clean, .PHONY, etc. to have one big list
#
targets  = $(debugbinaries) $(debuglibraries) $(releasebinaries) $(releaselibraries) STLport_d STLport_r


# Let make know these aren't real file names...
#
.PHONY: clean clobber distclean release debug $(targets)


# Eliminate all implicit rules just to be safe
#
.SUFFIXES:


# END: Variable Definitions
##############################################################################
# BEGIN: Targets


default: help
help:
	@-grep "^#=" $(MAKEFILE)


#####################################################################
# binaries (and test)
# 
# These are the release targets for the twixes
#
#This line expands to something like:
#
#twprint_r: STLport_r cryptlib_r core_r, fco_r, ...
#	/usr/bin/make -C twprint -f twprint.mak release "BUILDTYPE=r" "SYSPRE=i686-pc-linux"
#

$(releasebinaries) test_r: STLport_r $(releaselibraries)
	$(GMAKE) -C $(subst _r,,$@) -f $(subst _r,.mak,$@) release "SYSPRE=$(SYSPRE)"


# These are the debug targets for the twixes
#
#This line expands to something like:
#
#twprint_d: STLport_d cryptlib_d core_d, fco_d, ...
#	/usr/bin/make -C twprint -f twprint.mak debug "SYSPRE=i686-pc-linux"
#

$(debugbinaries) test_d: STLport_d $(debuglibraries)
	$(GMAKE) -C $(subst _d,,$@) -f $(subst _d,.mak,$@) debug "SYSPRE=$(SYSPRE)"


# Aliases:
# If 'make release|debug' is invoked, a log file is generated

release: 
	echo "\"MAKE RELEASE\"" > release.$(SYSPRE).out
	date >> release.$(SYSPRE).out
	echo "\"$(GMAKE) -f $(MAKEFILE) $(releasebinaries) | tee -a release.$(SYSPRE).out\"" >> release.$(SYSPRE).out
	$(GMAKE) -f $(MAKEFILE) $(releasebinaries) | tee -a release.$(SYSPRE).out
	date >> release.$(SYSPRE).out
debug: 
	echo "\"MAKE DEBUG\"" > debug.$(SYSPRE).out
	date >> debug.$(SYSPRE).out
	echo "\"$(GMAKE) -f $(MAKEFILE) $(debugbinaries) | tee -a debug.$(SYSPRE).out\"" >> debug.$(SYSPRE).out
	$(GMAKE) -f $(MAKEFILE) $(debugbinaries) | tee -a debug.$(SYSPRE).out
	date >> debug.$(SYSPRE).out

all: release debug


#####################################################################
# libraries
#
# These are release targets for each library.
# This line expands to something like:
#
#core_r:
#	/usr/bin/make/ -C core -f core.mak release "SYSPRE=i686-pc-linux"
#

$(releaselibraries):
	$(GMAKE) -C $(subst _r,,$@) -f $(subst _r,.mak,$@) release "SYSPRE=$(SYSPRE)"


# these are debug targets for each library. This expands to something like:
#core_d:
#	/usr/bin/make/ -C core -f core.mak debug "SYSPRE=i686-pc-linux"
#

$(debuglibraries):
	$(GMAKE) -C $(subst _d,,$@) -f $(subst _d,.mak,$@) debug "SYSPRE=$(SYSPRE)"

# crypto++ makes an executable, cryptest or cryptest_d
# Therefore it links (to STLport), so we have to add a dependency:

cryptlib_r: STLport_r
cryptlib_d: STLport_d


#####################################################################
# clobber clean distclean
#
# make clobber gets rid of all object files and the binaries
# (for everything except stlport, see distclean below)
#
# make clean gets rid of all object files but not the binaries
#

clobber clean:
	@libs='$(binaries) $(libraries) test'; \
	for lib in $$libs; do \
		echo "$@ing $$lib"; \
		$(GMAKE) -s -C $$lib -f $$lib.mak $@ "SYSPRE=$(SYSPRE)"; \
		rm -f $$lib/$$lib.$(SYSPRE).dep; \
	done;
# Don't call clobber on STLport cause we don't expect to change it often and 
# it takes a long time to build.
	$(GMAKE) -C $(STLPORT) -f STLport.mak clean "SYSPRE=$(SYSPRE)"


# make distclean does a clobber AND deletes STL libs as well
#
# this is its own directive since it takes so long to rebuild the
# STL libraries
#

distclean: clobber
	$(GMAKE) -C $(STLPORT) -f STLport.mak clobber "SYSPRE=$(SYSPRE)"
	- rm -rf $(LIBPRE)_r $(LIBPRE)_d
	- rm -rf $(BINPRE)_r $(BINPRE)_d
	- rm -f debug.$(SYSPRE).out
	- rm -f release.$(SYSPRE).out


#####################################################################
# STLport
#

STLport_r:	 
	$(GMAKE) -C $(STLPORT) -f STLport.mak release "SYSPRE=$(SYSPRE)"
STLport_d:
	$(GMAKE) -C $(STLPORT) -f STLport.mak debug "SYSPRE=$(SYSPRE)"



#####################################################################
# parser

#TODO: right now there is nothing to be done for the parser; we just
# use the MKS generated yylex.{cpp,h}, yyparse.{cpp,h}, all of which
# live in code/twparser.  Perhaps this section should go away???

#$(LIBPRE)_$(BUILDTYPE)/parser.a: parser/parser.mak parser/*.h
#	$(GMAKE) -C parser -f parser.mak $(BUILDTARGET)	 "SYSPRE=$(SYSPRE)"


# (End Targets)




