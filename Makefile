NAME = oscap-anaconda-addon

VERSION = 0.6

ADDON = org_fedora_oscap
TESTS = tests

FILES = $(ADDON) \
	$(TESTS) \
	po \
	COPYING \
	Makefile \
	README

EXCLUDES = \
	*.pyc

all:
	@echo "usage: make dist"
	@echo "       make test"
	@echo "       make install"
	@echo "       make uninstall"

DISTNAME = $(NAME)-$(VERSION)
ADDONDIR = /usr/share/anaconda/addons/
DISTBALL = $(DISTNAME).tar.gz
NUM_PROCS = $$(getconf _NPROCESSORS_ONLN)

install:
	mkdir -p $(DESTDIR)$(ADDONDIR)
	cp -rv $(ADDON) $(DESTDIR)$(ADDONDIR)
	$(MAKE) install-po-files

uninstall:
	rm -rfv $(DESTDIR)$(ADDONDIR)

dist:
	rm -rf $(DISTNAME)
	mkdir -p $(DISTNAME)
	@if test -d ".git"; \
	then \
		echo Creating ChangeLog && \
		( cd "$(top_srcdir)" && \
		  echo '# Generate automatically. Do not edit.'; echo; \
		  git log --stat --date=short ) > ChangeLog.tmp \
		&& mv -f ChangeLog.tmp $(DISTNAME)/ChangeLog \
		|| ( rm -f ChangeLog.tmp ; \
		     echo Failed to generate ChangeLog >&2 ); \
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi
	for file in $(FILES); do \
		cp -rpv $$file $(DISTNAME)/$$file; \
	done
	for excl in $(EXCLUDES); do \
		find $(DISTNAME) -name "$$excl" -delete; \
	done
	tar -czvf $(DISTBALL) $(DISTNAME)
	rm -rf $(DISTNAME)

potfile:
	$(MAKE) -C po potfile

po-pull:
	tx pull -a --disable-overwrite

install-po-files:
	$(MAKE) -C po install

test:
	@echo "***Running pylint checks***"
	@find . -name '*.py' -print|xargs -n1 --max-procs=$(NUM_PROCS) pylint -E 2> /dev/null
	@echo "[ OK ]"
	@echo "***Running unittests checks***"
	@PYTHONPATH=. nosetests --processes=-1 -vw tests/

runpylint:
	@find . -name '*.py' -print|xargs -n1 --max-procs=$(NUM_PROCS) pylint -E 2> /dev/null
	@echo "[ OK ]"

unittest:
	PYTHONPATH=. nosetests --processes=-1 -vw tests/
