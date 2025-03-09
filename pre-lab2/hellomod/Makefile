
obj-m     += hellomod.o
ccflags-y += -DEXPORT_SYMTAB

all: hello
	make -C ../vm/dist/modulebuild M=$(PWD) modules

hello: hello.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f hello
	make -C ../vm/dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../vm/dist/rootfs/modules
	cp hello hellomod.ko ../vm/dist/rootfs/modules
