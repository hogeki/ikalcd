KERNEL_PATH?=/usr/src/linux-headers-$(shell uname -r)

EXTRA_CFLAGS=-I$(shell pwd)

obj-m:=ikalcd.o

all:
	$(MAKE) modules -C $(KERNEL_PATH) SUBDIRS=$(shell pwd)
