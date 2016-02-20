# XSL stylesheets downloaded from http://docbook.sourceforge.net/release/xsl/current/html/
# Makefile from BitBake/OpenEmbedded manuals

EXTRA_DEPS = gen-nitb-vty-docbook

topdir = .
nitb_reference = $(topdir)/osmonitb-vty-reference.xml
manuals = $(nitb_reference)
# types = pdf txt rtf ps xhtml html man tex texi dvi
# types = pdf txt
types = $(docbooktotypes)
docbooktotypes = pdf
# htmlcssfile =
# htmlcss =

TOPDIR := ..
ASCIIDOCS := osmonitb-usermanual

include $(TOPDIR)/build/Makefile.asciidoc.inc
include $(TOPDIR)/build/Makefile.inc

osmonitb-usermanual.pdf: chapters/*.adoc

clean:
	rm -rf $(cleanfiles)

gen-nitb-vty-docbook: FORCE
	$(call command,xsltproc -o generated/combined1.xml \
		--stringparam with $(PWD)/../common/vty_additions.xml \
		$(MERGE_DOC) vty/nitb_vty_reference.xml, \
		XSLTPROC,Merging Common VTY)
	$(call command,xsltproc -o generated/combined2.xml \
		--stringparam with $(PWD)/../common/bsc_vty_additions.xml \
		$(MERGE_DOC) generated/combined1.xml, \
		XSLTPROC,Merging Common BSC VTY)
	$(call command,xsltproc -o generated/combined3.xml \
		--stringparam with $(PWD)/vty/nitb_vty_additions.xml \
		$(MERGE_DOC) generated/combined2.xml, \
		XSLTPROC,Merging NITB VTY)
	$(call command,xsltproc ../vty_reference.xsl generated/combined3.xml > generated/docbook_vty.xml, \
		XSLTPROC,Converting NITB VTY to DocBook)
