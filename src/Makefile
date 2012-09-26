#
# Variables needed to build the kernel module
#
name      = netlog
src_files = inet_utils.c probes.c whitelist.c connection.c proc_config.c

obj-m += $(name).o
$(name)-objs := $(src_files:.c=.o)

all: build

.PHONY: build install clean

build: clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y

install: build
	-mkdir -p /lib/modules/`uname -r`/kernel/arch/x86/kernel/
	cp $(name).ko /lib/modules/`uname -r`/kernel/arch/x86/kernel/
	depmod /lib/modules/`uname -r`/kernel/arch/x86/kernel/$(name).ko

clean:
	[ -d /lib/modules/$(shell uname -r)/build ] && \
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

