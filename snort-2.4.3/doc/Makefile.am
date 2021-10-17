## $Id: Makefile.am,v 1.21.2.2.2.3 2005/07/21 04:24:43 roesch Exp $
AUTOMAKE_OPTIONS=foreign no-dependencies

EXTRA_DIST = AUTHORS NEWS BUGS README \
CREDITS \
snort_manual.pdf snort_manual.tex INSTALL USAGE \
README.alert_order \
README.event_queue \
README.csv \
README.database \
README.FLEXRESP \
README.flow \
README.flow-portscan \
README.http_inspect \
README.PLUGINS \
README.thresholding \
README.UNSOCK \
README.WIN32 \
README.flowbits \
README.asn1 \
README.INLINE \
README.sfportscan \
README.frag3 \
snort_schema_v106.pdf \
README.wireless PROBLEMS RULES.todo WISHLIST faq.pdf faq.tex

DISTCLEANFILES= snort_manual.log snort_manual.toc snort_manual.aux faq.log faq.toc faq.aux snort_manual.pdf faq.pdf snort_manual.out

doc_DIR = $(prefix)/doc

SUFFIXES = .tex .dvi .ps

.tex.dvi:
	pslatex $< && pslatex $< && pslatex $<

.dvi.ps:
	dvips $< -o

.ps.pdf:
	ps2pdf $<

# perhaps one day, we will have a Makefile in the signatures directory...
# SUBDIRS = signatures
