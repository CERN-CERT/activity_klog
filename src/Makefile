#
# Variables needed to build the kernel module
#

kernel_version?= $(shell uname -r)
kernel_build?= /lib/modules/${kernel_version}/build
kernel_install?= /lib/modules/${kernel_version}/kernel/arch/x86/kernel

all: build

.PHONY: build install clean

build:
	make -C ${kernel_build} M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y

install: build
	make -C ${kernel_build} M=$(PWD) modules_install CONFIG_DEBUG_SECTION_MISMATCH=y

clean:
	[ -d ${kernel_build} ] && \
	make -C ${kernel_build} M=$(PWD) clean

