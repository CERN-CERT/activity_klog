#+++############################################################################
#                                                                              #
# RPMs building                                                                #
#                                                                              #
#---############################################################################

TOP 	  := $(dir $(lastword $(MAKEFILE_LIST)))
NAME 	  := $(shell basename ${TOP}/*.spec .spec)
VERSION   := $(shell egrep '^Version:' ${TOP}/${NAME}.spec | sed 's/^Version:\s*//')
RELEASE   := ${NAME}-${VERSION}

rpmtopdir := $(shell rpm --eval %_topdir)
rpmbuild  := $(shell [ -x /usr/bin/rpmbuild ] && echo rpmbuild || echo rpm)
git       := git

#
# define DIST for non-default build dists (e.g. make DIST=.slc6 rpm)
# ... or export DIST=.slc6 ; make rpm
#
DIST	  ?= $(shell rpm --eval %dist)

all: srpm

dist: clean 
	@(cd src && git archive --format=tar --prefix=$(NAME)-$(VERSION)/ $(VERSION)) \
		| gzip > $(NAME)-$(VERSION).tgz
	@(cd config-src && git archive --format=tar --prefix=config/ $(VERSION)) \
		| gzip > $(NAME)-config-$(VERSION).tgz

srpm: dist
	$(rpmbuild) --define "dist $(DIST)" --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -bs ${NAME}.spec

rpm: dist 
	$(rpmbuild) --define "dist $(DIST)" --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -ba ${NAME}.spec

clean:
	@rm -f *.tgz
	@rm -f *.rpm
	@git clean -Xdf
