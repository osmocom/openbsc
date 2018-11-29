OSMO_GSM_MANUALS_DIR := $(shell ../osmo-gsm-manuals-dir.sh)
srcdir=$(CURDIR)

ASCIIDOC = osmonitb-usermanual.adoc
ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

VTY_REFERENCE = osmonitb-vty-reference.xml
include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
