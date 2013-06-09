#
# Variables needed to build the kernel module
#
name      = netlog
src_files = inet_utils.c probes.c whitelist.c log.c proc_config.c netlog_module.c 

obj-m += $(name).o
$(name)-y := $(src_files:.c=.o)
ccflags-y  += -D'MODULE_NAME="netlog"'

kernel_version = $(shell uname -r)

all: build

.PHONY: build install clean

build: clean
	make -C /lib/modules/${kernel_version}/build M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y

install: build
	-mkdir -p /lib/modules/${kernel_version}/kernel/arch/x86/kernel/
	cp $(name).ko /lib/modules/${kernel_version}/kernel/arch/x86/kernel/
	depmod /lib/modules/${kernel_version}/kernel/arch/x86/kernel/$(name).ko

clean:
	[ -d /lib/modules/${kernel_version}/build ] && \
	make -C /lib/modules/${kernel_version}/build M=$(PWD) clean

