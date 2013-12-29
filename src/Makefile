#
# Variables needed to build the kernel module
#

obj-m += secure_logs/
obj-m += netlog/

kernel_version = $(shell uname -r)
kernel_build= /lib/modules/${kernel_version}/build
kernel_install = /lib/modules/${kernel_version}/kernel/arch/x86/kernel

all: build

.PHONY: build install clean

build:
	make -C ${kernel_build} M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y

install: build
	-mkdir -p ${kernel_install}
	cp $(name).ko ${kernel_install}/
	depmod ${kernel_install}/$(name).ko

clean:
	[ -d ${kernel_build} ] && \
	make -C ${kernel_build} M=$(PWD) clean

