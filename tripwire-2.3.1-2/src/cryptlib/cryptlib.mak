#
# cryptlib.mak
#
# This make acts as an intermediate between the main makefile and crypto++.mak
# so that handling of libraries from main makefile is uniform--implementation
# details are kept in sub-directories (sub-packages)

#  Include system specific defines
#  (All that is actually needed is GMAKE, LIBPRE, and LIBDIR)
include ../make_include/$(SYSPRE).inc


#####################################################################
# crypto++
#
# Note: We MUST do a clean in the crypto++ dir before building a
# release or debug cryptlib.a.  This is because the .o files for 
# crypto++ are stored in the same place for both debug and release
# builds.  If we don't do a clean, we may build a debug lib with
# release .o files, or vice-versa.


#The actual name of the file is used as a target so that it doesn't call
#clean if the target exists

default:
	@echo Usage:  make -f cryptlib.mak [release|debug] "SYSPRE=[ i686-pc-linux | ... ]"

release: $(LIBPRE)_r/cryptlib.a
$(LIBPRE)_r/cryptlib.a:
	test -d $(LIBDIR) || mkdir $(LIBDIR)
	test -d $(LIBPRE)_r || mkdir $(LIBPRE)_r
	$(GMAKE) -f $(SYSPRE).mak clean		  # We must clean crypto++ before building
	$(GMAKE) -f $(SYSPRE).mak release 
	cp cryptlib.a $@

debug: $(LIBPRE)_d/cryptlib.a
$(LIBPRE)_d/cryptlib.a: 
	test -d $(LIBDIR) || mkdir $(LIBDIR)
	test -d $(LIBPRE)_d || mkdir $(LIBPRE)_d
	$(GMAKE) -f $(SYSPRE).mak clean		  # We must clean crypto++ before building
	$(GMAKE) -f $(SYSPRE).mak debug
	cp cryptlib_d.a $@


clean:
	$(GMAKE) -f $(SYSPRE).mak clean

clobber:
	$(GMAKE) -f $(SYSPRE).mak clobber
	rm -f $(LIBPRE)_r/cryptlib.a
	rm -f $(LIBPRE)_d/cryptlib.a