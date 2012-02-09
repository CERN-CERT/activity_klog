name      = netlog
src_files = iputils.c probes.c whitelist.c

obj-m += $(name).o
$(name)-objs := $(src_files:.c=.o)

srcrpm: archive
	rpmbuild --define "_sourcedir ${PWD}" --define "_srcrpmdir ${PWD}" -bs $(name).spec

archive: 
	rm -f $(name).tar.gz
	tar --exclude .git --exclude kmodtool.sh --exclude $(name).spec -zchf $(name).tar.gz *
