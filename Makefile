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

#
# define DIST for non-default build dists (e.g. make DIST=.slc6 rpm)
# ... or export DIST=.slc6 ; make rpm
#
DIST	  ?= $(shell rpm --eval %dist)

all: srpm

dist: clean 
	-rm -rf /var/tmp/${RELEASE}
	-rm -rf /var/tmp/${RELEASE}-buildroot
	-mkdir /var/tmp/${RELEASE}
	cp -r * /var/tmp/${RELEASE}
	cd /var/tmp/ ; tar cvfz ${RELEASE}.tar.gz \
                    --exclude-vcs --exclude='*~' --exclude='#*#' --exclude='20*' ${RELEASE}  
	cp /var/tmp/${RELEASE}.tar.gz .


sources: dist

srpm: dist
	$(rpmbuild) --define "dist $(DIST)" --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -bs ${NAME}.spec; \
	rm ${NAME}-${VERSION}.tar.gz

rpm: dist 
	$(rpmbuild) --define "dist $(DIST)" --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -ba ${NAME}.spec; \
        rm ${NAME}-${VERSION}.tar.gz

clean:
	@rm -f *.tar.gz
	@rm -f *.rpm
