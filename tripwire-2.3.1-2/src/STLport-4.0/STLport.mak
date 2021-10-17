##############################################################################
# STLport Makefile for Tripwire
# 
# This Makefile acts as an intermediary between the top level Makefile and
# the STLport make process.  The STLport makefile ./src/gcc.mak takes
# quite a while to rebuild STLport even if there is nothing to be done.
# This makefile tries only call stlport makefile if the stl libraries 
# don't exist.
##############################################################################


##############################################################################
# BEGIN: Configuration section

MAKEFILE = STLport.mak

#-----------------------------------------------------------------------------
# Include master Makefile.inc
#
# Please examine this file for configuration parameters as well.
# (All that is actually used is LIBDIR, LIBPRE and GMAKE.)

include ../make_include/$(SYSPRE).inc

# END: Configuration section
##############################################################################

# Library objects that gcc.mak creates
STLLIB_R = libstlport_gcc.a #libstlport_gcc_debug.a libstlport_gcc_stldebug.a
STLLIB_D = libstlport_gcc.a

# Make must be invoked with SYSPRE defined
default:
	@echo Usage:  make -f STLport.mak [release|debug] "SYSPRE=[i686-pc-linux|...]"

release: $(LIBPRE)_r/$(STLLIB_R)
debug: $(LIBPRE)_d/$(STLLIB_D)

$(LIBPRE)_r/$(STLLIB_R):
	test -d $(LIBDIR) || mkdir $(LIBDIR)
	test -d $(LIBPRE)_r || mkdir $(LIBPRE)_r
	test -e "include" || test "x$(SYSPRE)" != "xi386-unknown-freebsd" || ln -s /usr/include/g++ include
	test -e "include" || test "x$(SYSPRE)" != "xi386-unknown-openbsd" || ln -s /usr/include/g++ include
	export PATH=./stlport:${PATH}; $(GMAKE) -C ./src -f gcc.mak clobber
	$(GMAKE) -f $(MAKEFILE) lib/$(STLLIB_R)
	cp lib/$(STLLIB_R) $@
	
$(LIBPRE)_d/$(STLLIB_D):
	test -d $(LIBDIR) || mkdir $(LIBDIR)
	test -d $(LIBPRE)_d || mkdir $(LIBPRE)_d
	test -e "include" || test "x$(SYSPRE)" != "i386-unknown-freebsd" || ln -s /usr/include/g++ include
	test -e "include" || test "x$(SYSPRE)" != "i386-unknown-openbsd" || ln -s /usr/include/g++ include
	export PATH=./stlport:${PATH}; $(GMAKE) -C ./src -f gcc.mak clobber
	$(GMAKE) -f $(MAKEFILE) lib/$(STLLIB_D)
	cp lib/$(STLLIB_D) $@

#####################################################################
# STLport
#
# We need to add stlport at the beginning of the path before building.
# See INSTALL in STLport for more info.

STLport: ${addprefix lib/, $(STLLIBS)}

#lib/$(STLLIB_R) lib/$(STLLIB_D):  #  Switch these rule lines if STLLIB_R
lib/$(STLLIB_R):                   #  and STLLIB_D ever become different
	export PATH=./stlport:${PATH}; $(GMAKE) -C ./src -f gcc.mak ../$@

clean:
	export PATH=./stlport:${PATH}; $(GMAKE) -C ./src -f gcc.mak clean

clobber:
	export PATH=./stlport:${PATH}; $(GMAKE) -C ./src -f gcc.mak clobber
	rm -f $(LIBPRE)_r/$(STLLIB_R)
	rm -f $(LIBPRE)_d/$(STLLIB_D)
	test "x$(SYSPRE)" != "xi386-unknown-freebsd" || rm -f include
	test "x$(SYSPRE)" != "xi386-unknown-openbsd" || rm -f include

