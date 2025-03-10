
obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all: crypto
	make -C ../vm/dist/modulebuild M=$(PWD) modules

crypto: crypto.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f crypto
	make -C ../vm/dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../vm/dist/rootfs/modules
	cp crypto cryptomod.ko ../vm/dist/rootfs/modules
