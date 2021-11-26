NAME = oscap-anaconda-addon

VERSION = 0.35.0

ADDON = org_fedora_oscap
TESTS = tests \
	testing_files

DEFAULT_INSTALL_OF_PO_FILES ?= yes

PYVERSION = -3

TRANSLATIONS_DIR ?= po

FILES = $(ADDON) \
	$(TESTS) \
	data \
	po \
	COPYING \
	Makefile \
	README.md

EXCLUDES = \
	*~ \
	*.pyc

L10N_REPO_RELATIVE_PATH ?= OpenSCAP/oscap-anaconda-addon-l10n.git
L10N_REPOSITORY ?= https://github.com/$(L10N_REPO_RELATIVE_PATH)
L10N_REPOSITORY_RW ?= git@github.com:$(L10N_REPO_RELATIVE_PATH)
# Branch used in anaconda-l10n repository.
# This should be master all the time, unless you are testing translation PRs.
GIT_L10N_BRANCH ?= master
# The base branch, used to pair code with translations
OAA_PARENT_BRANCH ?= master

all:

DISTNAME = $(NAME)-$(VERSION)
ADDONDIR = /usr/share/anaconda/addons/
SERVICEDIR = /usr/share/anaconda/dbus/services/
CONFDIR = /usr/share/anaconda/dbus/confs/
DISTBALL = $(DISTNAME).tar.gz
NUM_PROCS = $$(getconf _NPROCESSORS_ONLN)

install:
	mkdir -p $(DESTDIR)$(ADDONDIR)
	mkdir -p $(DESTDIR)$(SERVICEDIR)
	mkdir -p $(DESTDIR)$(CONFDIR)
	cp -rv $(ADDON) $(DESTDIR)$(ADDONDIR)
	install -c -m 644 data/*.service $(DESTDIR)$(SERVICEDIR)
	install -c -m 644 data/*.conf $(DESTDIR)$(CONFDIR)
ifeq ($(DEFAULT_INSTALL_OF_PO_FILES),yes)
	$(MAKE) install-po-files
endif

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

# po-pull and update-pot are "inspired" by corresponding Anaconda code at
# https://github.com/rhinstaller/anaconda/blob/master/Makefile.am
# Our use case is slightly simpler (only one pot file), but we don't use automake,
# so there have to be some differences.

po-pull:
	TEMP_DIR=$$(mktemp --tmpdir -d oscap-anaconda-addon-l10n-XXXXXXXXXX) && \
	git clone --depth 1 -b $(GIT_L10N_BRANCH) -- $(L10N_REPOSITORY) $$TEMP_DIR && \
	mkdir -p $(TRANSLATIONS_DIR) && \
	cp $$TEMP_DIR/$(OAA_PARENT_BRANCH)/*.po $(TRANSLATIONS_DIR)/ && \
	rm -rf $$TEMP_DIR

# This algorithm will make these steps:
# - clone localization repository
# - copy pot file to this repository
# - check if pot file is changed (ignore the POT-Creation-Date otherwise it's always changed)
# - if not changed:
#   - remove cloned repository
# - if changed:
#   - add pot file
#   - commit pot file
#   - tell user to verify this file and push to the remote from the temp dir
POTFILE_BASENAME = oscap-anaconda-addon.pot
update-pot:
	$(MAKE) -C po potfile
	TEMP_DIR=$$(mktemp --tmpdir -d oscap-anaconda-addon-l10n-XXXXXXXXXX) || exit 1 ; \
	git clone --depth 1 -b $(GIT_L10N_BRANCH) -- $(L10N_REPOSITORY_RW) $$TEMP_DIR || exit 2 ; \
	mkdir -p $$TEMP_DIR/$(OAA_PARENT_BRANCH) ; \
	cp po/$(POTFILE_BASENAME) $$TEMP_DIR/$(OAA_PARENT_BRANCH)/ || exit 3 ; \
	pushd $$TEMP_DIR/$(OAA_PARENT_BRANCH) ; \
	git difftool --trust-exit-code -y -x "diff -u -I '^\"POT-Creation-Date: .*$$'" HEAD ./$(POTFILE_BASENAME) &>/dev/null ; \
	if [ $$? -eq 0  ] ; then \
		popd ; \
		echo "Pot file is up to date" ; \
		rm -rf $$TEMP_DIR ; \
	else \
		git add ./$(POTFILE_BASENAME) && \
		git commit -m "Update $(POTFILE_BASENAME)" && \
		popd && \
		echo "Pot file updated for the localization repository $(L10N_REPOSITORY)" && \
		echo "Please confirm changes (git diff HEAD~1) and push:" && \
		echo "$$TEMP_DIR" ; \
	fi ;

install-po-files:
	$(MAKE) -C po install RPM_BUILD_ROOT=$(DESTDIR)

CONTAINER_NAME = oscap-anaconda-addon-ci
container-test:
	podman build --tag $(CONTAINER_NAME) --file tests/Dockerfile
	podman run --volume .:/oscap-anaconda-addon:Z $(CONTAINER_NAME) make test

test: unittest runpylint

runpylint:
	@echo "***Running pylint checks***"
	python3 -m pylint org_fedora_oscap -E 2> /dev/null
	@echo "[ OK ]"

unittest:
	@echo "***Running unittests checks***"
	PYTHONPATH=. python3 -m pytest -v tests/
