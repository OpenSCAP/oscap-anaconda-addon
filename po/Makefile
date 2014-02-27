#
# taken from python-meh sources
# Makefile for the PO files (translation) catalog
#
# $Id$

TOP	 = ../..

# What is this package?
NLSPACKAGE	= oscap-anaconda-addon
POTFILE		= $(NLSPACKAGE).pot
INSTALL		= /usr/bin/install -c
INSTALL_DATA	= $(INSTALL) -m 644
INSTALL_DIR	= /usr/bin/install -d

# destination directory
INSTALL_NLS_DIR = $(RPM_BUILD_ROOT)/usr/share/locale

# PO catalog handling
MSGMERGE	= msgmerge -v
XGETTEXT	= xgettext --default-domain=$(NLSPACKAGE) \
		  --add-comments
MSGFMT		= msgfmt --statistics --verbose

# What do we need to do
POFILES		= $(wildcard *.po)
MOFILES		= $(patsubst %.po,%.mo,$(POFILES))
PYSRC		= $(wildcard ../org_fedora_oscap/*.py ../org_fedora_oscap/*/*.py ../org_fedora_oscap/*/*/*.py)
GLADEFILES = $(wildcard ../org_fedora_oscap/*/*/*.glade)

all::  update-po $(MOFILES)

potfile: $(PYSRC) glade-po
	$(XGETTEXT) -L Python --keyword=_ --keyword=N_ $(PYSRC) tmp/*.h
	@if cmp -s $(NLSPACKAGE).po $(POTFILE); then \
	    rm -f $(NLSPACKAGE).po; \
	else \
	    mv -f $(NLSPACKAGE).po $(POTFILE); \
	fi; \
	rm -rf tmp/

glade-po: $(GLADEFILES)
	rm -rf tmp/
	for f in $(GLADEFILES); do \
		intltool-extract --type=gettext/glade -l $$f ;\
	done

update-po: Makefile refresh-po

refresh-po: Makefile
	for cat in $(POFILES); do \
		lang=`basename $$cat .po`; \
		if $(MSGMERGE) $$lang.po $(POTFILE) > $$lang.pot ; then \
			mv -f $$lang.pot $$lang.po ; \
			echo "$(MSGMERGE) of $$lang succeeded" ; \
		else \
			echo "$(MSGMERGE) of $$lang failed" ; \
			rm -f $$lang.pot ; \
		fi \
	done

clean:
	@rm -fv *mo *~ .depend
	@rm -rf tmp

install: $(MOFILES)
	@for n in $(MOFILES); do \
	    l=`basename $$n .mo`; \
	    $(INSTALL_DIR) $(INSTALL_NLS_DIR)/$$l/LC_MESSAGES; \
	    $(INSTALL_DATA) --verbose $$n $(INSTALL_NLS_DIR)/$$l/LC_MESSAGES/$(NLSPACKAGE).mo; \
	done

uninstall:
	rm -rfv $(INSTALL_NLS_DIR)/*/LC_MESSAGES/$(NLSPACKAGE).mo

%.mo: %.po
	$(MSGFMT) -o $@ $<

.PHONY: missing depend

