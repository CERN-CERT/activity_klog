#
# Variables needed to build the kernel module
#
name      = netlog
version   = `cat VERSION`
src_files = inet_utils.c probes.c whitelist.c connection.c

obj-m += $(name).o
$(name)-objs := $(src_files:.c=.o)


#
# Distributions which src rpms are built for by default
# The corresponding spec file is needed: DIST/$(name).spec
#
DISTS    = slc5 slc6

#
# variables for all external commands (we try to be verbose)
#

GIT      = git
PERL     = perl
RPMBUILD = rpmbuild
SED      = sed

all: srpms

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

#+++############################################################################
#                                                                              #
# version management                                                           #
#                                                                              #
#---############################################################################

#
# internal targets
#

.PHONY: _increment_version _increment_release _update_spec _git_commit_tag

_increment_version:
	@$(PERL) -pi -e 'die("invalid version: $$_\n") unless \
	  s/^(\d+)\.(\d+)(.*?)$$/sprintf("%d.%d%s", $$1+1, 0, $$4)/e' VERSION

_increment_release:
	@$(PERL) -pi -e 'die("invalid version: $$_\n") unless \
	  s/^(\d+)\.(\d+)(.*?)$$/sprintf("%d.%d%s", $$1, $$2+1, $$4)/e' VERSION

_update_spec: $(DISTS:=.spec)

%.spec: dist.%/$(name).spec
	@version=`cat VERSION`; \
	$(SED) -i -e "s/^\(%define kmod_driver_version\s\+\)\S\+\s*$$/\1$$version/" $<

_git_commit_tag:
	@version=`cat VERSION`; \
	$(GIT) commit -a -m "global commit for version $$version" || exit 1; \
	tag="v$$version" ; \
	$(GIT) tag $$tag || exit 1; \
        $(GIT) push || exit 1; \
        $(GIT) push origin $$tag || exit 1; \
	echo "New version is $$version (tag $$tag)"

#
# standard targets
#

version:    _increment_version _update_spec _git_commit_tag

release:    _increment_release _update_spec _git_commit_tag


#+++############################################################################
#                                                                              #
# RPMs building                                                                #
#                                                                              #
#---############################################################################


dist:
	@version=`cat VERSION`; \
	git archive --format=tar --prefix=$(name)-$$version/ v$$version \
	| tar --delete "$(name)-$$version/dist.*" --delete "$(name)-$$version/webpage" --delete "$(name)-$$version/.git*" \
	| gzip > $(name)-$$version.tgz

srpms: dist $(DISTS:=.srpm)

slc5.srpm: dist.slc5/$(name).spec
	@version=`cat VERSION`; \
	cp $(name)-$$version.tgz dist.slc5/; \
	$(RPMBUILD) --define "_sourcedir ${PWD}/dist.slc5" --define "_srcrpmdir ${PWD}/rpms" --define "dist .slc5" --define '_source_filedigest_algorithm 1' --define '_binary_filedigest_algorithm 1' --define '_binary_payload w9.gzdio' -bs $<; \
	rm dist.slc5/$(name)-$$version.tgz

%.srpm: dist.%/$(name).spec
	@version=`cat VERSION`; \
	cp $(name)-$$version.tgz dist.$*/; \
	$(RPMBUILD) --define "_sourcedir ${PWD}/dist.$*" --define "_srcrpmdir ${PWD}/rpms" --define "dist .$*" -bs $<; \
	rm dist.$*/$(name)-$$version.tgz

%.rpm: %.srpm
	@version=`cat VERSION`; \
	rpmbuild --rebuild --define '_rpmdir ${PWD}/rpms' --define 'dist .$*' $(name)-$$version-1.$*.src.rpm

dist.clean:
	@rm -f *tgz

version:
	@echo $(version)
