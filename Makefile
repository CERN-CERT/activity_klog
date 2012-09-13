#
# Variables needed to build the kernel module
#
name      = netlog
src_files = inet_utils.c probes.c whitelist.c connection.c proc_config.c

obj-m += $(name).o
$(name)-objs := $(src_files:.c=.o)

all: build

.PHONY: build install build.clean

clean: build.clean 

build: build.clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y

install: build
	-mkdir -p /lib/modules/`uname -r`/kernel/arch/x86/kernel/
	cp $(name).ko /lib/modules/`uname -r`/kernel/arch/x86/kernel/
	depmod /lib/modules/`uname -r`/kernel/arch/x86/kernel/$(name).ko

build.clean:
	[ -d /lib/modules/$(shell uname -r)/build ] && \
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


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

dist: dist.clean 
	-rm -rf /var/tmp/${RELEASE}
	-rm -rf /var/tmp/${RELEASE}-buildroot
	-mkdir /var/tmp/${RELEASE}
	cp -r * /var/tmp/${RELEASE}
	cd /var/tmp/ ; tar cvfz ${RELEASE}.tar.gz \
                    --exclude-vcs --exclude='*~' --exclude='#*#' --exclude='20*' ${RELEASE}  
	cp /var/tmp/${RELEASE}.tar.gz .


sources: dist

srpm: dist
	$(rpmbuild)  --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -bs ${NAME}.spec; \
	rm ${NAME}-${VERSION}.tar.gz

rpm: dist 
	$(rpmbuild) --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -ba ${NAME}.spec; \
        rm ${NAME}-${VERSION}.tar.gz

dist.clean:
	@rm -f *.tar.gz
	@rm -f *.rpm
