#run make -C /lib/modules/$(shell uname -r)/build M=$(PWD) in order to compile

obj-m += netlog.o

all: make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean: make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
