obj-m := wrapfs.o
wrapfs-objs := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all: wrapfs pass_key

wrapfs:
	$(MAKE) -C $(KERNELDIR)  M=$(PWD)  modules

pass_key:
	gcc -Wall -Werror pass_key.c -o pass_key -lssl

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f pass_key

