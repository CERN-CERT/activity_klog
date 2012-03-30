name      = netlog
src_files = iputils.c probes.c whitelist.c logger.c

obj-m += $(name).o
$(name)-objs := $(src_files:.c=.o)

srcrpm: archive slc5 slc6

slc5:
	rpmbuild --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" --define 'dist .slc5' -bs $(name).spec

slc6:
	rpmbuild --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" --define 'dist .slc6' -bs $(name).spec

archive: 
	rm -f $(name).tar.gz
	tar --exclude .git --exclude *.rpm --exclude kmodtool.sh --exclude $(name).spec -zchf $(name).tar.gz *
