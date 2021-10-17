AUTOMAKE_OPTIONS = foreign no-dependencies

########################################################################
##
## libhoneyd, the honeyd preload library. Wrapped around
## server applications to make them communicate through
## honeyd.
##
########################################################################

## Preload library
## This is how it should work but libtool is so broken
#pkglib_LTLIBRARIES = libhoneyd.la 
#libhoneyd_la_SOURCES = honeyd_overload.c atomicio.c fdpass.c fdpass.h
#libhoneyd_la_LDFLAGS = -module -export-dynamic -avoid-version

## Bad hack with help from marius@monkey.org to actually get this 
## working on Linux
LIBHONEYDFILES= honeyd_overload.lo atomicio.lo fdpass.lo
libhoneyd.so: $(LIBHONEYDFILES)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o libtmp$@.la \
		-rpath $(libdir)/honeyd $(LIBHONEYDFILES) $(LIBS) $(LDFLAGS) \
		-module -avoid-version -nostdlib @LIBDL@
	rm -f libtmp$@.la tmp$@.so* $@
	cp .libs/libtmp$@.so $@ || cp .libs/libtmp$@ $@
	rm -f .libs/libtmp$@.*

libhoneyddir = $(libdir)/honeyd
libhoneyd_DATA = libhoneyd.so


# Configuration files for Honeyd
honeyddatadir = $(datadir)/honeyd
honeydlibdir = $(libdir)/honeyd
honeydincludedir = $(includedir)/honeyd
honeyddata_DATA = README nmap.assoc xprobe2.conf nmap.prints config.sample \
		config.ethernet pf.os

honeydplugins = @PLUGINS@
honeydpluginsdeclare = @PLUGINSDECLARE@

########################################################################
##
## Honeyd itself. It uses plugins, so we need to install a few header
## files that plugins can pick up when being built so that they know
## how to register etc.
##
########################################################################

bin_PROGRAMS = honeyd honeydctl

# Install the header files in a separate subdirectory. Note that
# honeydincludedir is the directory reported to the user, who has to
# use that directory as an -I include directive with #include <honeyd/foo.h>.
# pkgincludedir includes the additional honeyd directory since that's
# where the headers are actually installed.
pkgincludedir = $(honeydincludedir)
pkginclude_HEADERS = hooks.h plugins.h plugins_config.h debug.h

honeyd_SOURCES	= honeyd.c command.c parse.y lex.l config.c personality.c \
	util.c ipfrag.c router.c tcp.c udp.c xprobe_assoc.c log.c \
	fdpass.c atomicio.c subsystem.c hooks.c plugins.c \
	plugins_config.c pool.c interface.c arp.c gre.c \
	honeyd.h personality.h ipfrag.h	router.h tcp.h udp.h parse.h \
	xprobe_assoc.h subsystem.h fdpass.h hooks.h plugins.h \
	plugins_config.h template.h pool.h interface.h arp.h gre.h \
	log.h pfctl_osfp.c pf_osfp.c pfvar.h condition.c condition.h \
	osfp.c osfp.h ui.c ui.h buffer.h buffer.c ethernet.c ethernet.h \
	parser.h

honeyd_DEPENDENCIES = @PYEXTEND@ @LIBOBJS@
honeyd_LDADD = @PYEXTEND@ @LIBOBJS@ @PYTHONLIB@ @EVENTLIB@ @PCAPLIB@ \
	@DNETLIB@ @PLUGINLIB@ -lm

# Allow plugins to use honeyd's functions:
honeyd_LDFLAGS = -export-dynamic 

honeydctl_SOURCES = honeydctl.c
honeydctl_LDADD = @LIBOBJS@ @EDITLIB@ @LIBCURSES@
honeydctl_INCLUDES = @EDITINC@
honeydctl_CFLAGS = -O2 -Wall

CFLAGS	= -O2 -Wall -g \
	-DPATH_HONEYDINCLUDE="\"$(honeydincludedir)\"" \
	-DPATH_HONEYDDATA="\"$(honeyddatadir)\"" \
	-DPATH_HONEYDLIB="\"$(honeydlibdir)\"" \
	-DHONEYD_PLUGINS_DECLARE="$(honeydpluginsdeclare)" \
	-DHONEYD_PLUGINS="$(honeydplugins)"

INCLUDES = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@PYTHONINC@ @EVENTINC@ @PCAPINC@ @DNETINC@

########################################################################
##
## Miscellaneous stuff -- files we need to include in the package,
## manpage, yacc/lex stuff etc.
##
########################################################################

man_MANS = honeyd.8 honeydctl.1

EXTRA_DIST = $(man_MANS) acconfig.h $(honeyddata_DATA) \
	LICENSE \
	compat/sys/tree.h compat/sys/queue.h compat/err.h \
	compat/libdnet/dnet.h compat/getopt.h \
	scripts/web.sh scripts/router-telnet.pl scripts/test.sh \
	scripts/mydoom.pl scripts/README.mydoom \
	scripts/smtp.pl scripts/proxy.pl \
	scripts/snmp/README scripts/snmp/buildSNMPConfig.pl \
	scripts/snmp/fake-snmp.pl scripts/snmp/default.snmp \
	scripts/snmp/windows2000.snmp.tpl scripts/snmp/linux-2.4.snmp.tpl \
	ltconfig honeyd_overload.c pyextend.c pyextend.h

dist-hook:
	./distribute.py $(distdir)/

CLEANFILES = *.so
DISTCLEANFILES = *~

LEX_OUTPUT_ROOT = lex.hyd
LFLAGS  = -Phyd
YFLAGS  = -d
