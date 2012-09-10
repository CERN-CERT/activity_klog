#
# Variables needed to build the kernel module
#
name      = netlog
src_files = inet_utils.c probes.c whitelist.c connection.c proc_config.c

obj-m += $(name).o
$(name)-objs := $(src_files:.c=.o)

#
# Get current version number
# 
version   = $(shell if [ -f VERSION ]; then cat VERSION | cut -d- -f1; fi)
release   = $(shell if [ -f VERSION ]; then cat VERSION | cut -d- -f2; fi)

#
# variables for all external commands (we try to be verbose)
#

GIT       = git
PERL      = perl
RPMBUILD  = rpmbuild
SED       = sed

all: srpm

.PHONY: build install build.clean

clean: dist.clean build.clean 

build: hashed_symbols.h
	./extractSymAddrs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y

install: build
	-mkdir -p /lib/modules/`uname -r`/kernel/arch/x86/kernel/
	cp $(name).ko /lib/modules/`uname -r`/kernel/arch/x86/kernel/
	depmod /lib/modules/`uname -r`/kernel/arch/x86/kernel/$(name).ko

build.clean:
	[ -d /lib/modules/$(shell uname -r)/build ] && \
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f hashed_static_symbols.h

#+++############################################################################
#                                                                              #
# version management                                                           #
#                                                                              #
#---############################################################################

#
# internal targets
#

.PHONY: _increment_version _increment_release _increment_release_build _git_commit_tag

_increment_version:
	@$(PERL) -pi -e 'die("invalid version: $$_\n") unless \
	  s/^(\d+)\.(\d+)-\d+(.*?)$$/sprintf("%d.%d-%d%s", $$1+1, 0, 1, $$3)/e' VERSION

_increment_release:
	@$(PERL) -pi -e 'die("invalid version: $$_\n") unless \
	  s/^(\d+)\.(\d+)-\d+(.*?)$$/sprintf("%d.%d-%d%s", $$1, $$2+1, 1, $$3)/e' VERSION

_increment_release_build:
	@$(PERL) -pi -e 'die("invalid version: $$_\n") unless \
	  s/^(\d+)\.(\d+)-(\d+)(.*?)$$/sprintf("%d.%d-%d%s", $$1, $$2, $$3+1, $$4)/e' VERSION

_update_spec: $(name).spec
	@version=`cat VERSION | cut -d- -f1`; \
	$(SED) -i -e "s/^\(%define kmod_driver_version\s\+\)\S\+\s*$$/\1$$version/" $<
	@release=`cat VERSION | cut -d- -f2`; \
	$(SED) -i -e "s/^\(%define kmod_rpm_release\s\+\)\S\+\s*$$/\1$$release/" $<

_git_commit_tag:
	@version=`cat VERSION | cut -d- -f1`; \
	$(GIT) commit -a -m "global commit for version $(version)" || exit 1; \
	tag="v$(version)" ; \
	$(GIT) tag $$tag || exit 1; \
        $(GIT) push || exit 1; \
        $(GIT) push origin $$tag || exit 1; \
	echo "New version is $(version) (tag $$tag)"

_git_force_commit_tag:
	@version=`cat VERSION | cut -d- -f1`; \
	$(GIT) commit -a -m "global commit for version $(version)" || exit 1; \
	tag="v$(version)" ; \
	$(GIT) tag -f $$tag || exit 1; \
        $(GIT) push || exit 1; \
        $(GIT) push origin $$tag || exit 1; \
	echo "New version is $(version) (tag $$tag)"

#
# standard targets
#

version:       _increment_version _update_spec _git_commit_tag

release:       _increment_release _update_spec _git_commit_tag

release_build: _increment_release_build _update_spec _git_force_commit_tag


#+++############################################################################
#                                                                              #
# RPMs building                                                                #
#                                                                              #
#---############################################################################


dist: $(name)-$(version).tgz

%.tgz:
	@git archive --format=tar --prefix=$(name)-$(version)/ v$(version) \
	| tar --delete "$(name)-$(version)/.git*" \
	| gzip > $(name)-$(version).tgz


srpm: dist
	$(RPMBUILD) --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -bs $(name).spec; \
	rm $(name)-$(version).tgz

rpm: dist 
	$(RPMBUILD) --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -ba $(name).spec; \
        rm $(name)-$(version).tgz

dist.clean:
	@rm -f *.tgz
	@rm -f *.rpm
