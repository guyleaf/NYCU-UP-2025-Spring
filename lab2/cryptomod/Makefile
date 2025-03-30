
obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all:
	make -C ../vm/dist/modulebuild M=$(PWD) modules

clean:
	make -C ../vm/dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../vm/dist/rootfs/modules
	cp cryptomod.ko ../vm/dist/rootfs/modules
