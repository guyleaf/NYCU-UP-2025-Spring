SHELL 			= /bin/sh

#### Start of system configuration section. ####

C				= gcc
CFLAGS			= -std=c17 -Wall -Wextra
LDFLAGS			= -ldl -lcapstone

prefix 			= .
srcdir			= $(prefix)
# sampledir 		= $(prefix)/sample
# toolsdir		= $(prefix)/tools

#### End of system configuration section. ####

PROGS			= libzpoline.so.1 libzpoline.so.2 libzpoline.so

# search dependencies
vpath %.c $(srcdir)

.PHONY: all
all: main

libzpoline.so: libzpoline.o
	$(C) -shared -o $@ $< $(LDFLAGS)

libzpoline.so.%: libzpoline.o.%
	$(C) -shared -o $@ $< $(LDFLAGS)

libzpoline.o: libzpoline.c
	$(C) -fPIC $(CFLAGS) -c -o $@ $<

libzpoline.o.%: libzpoline%.c
	$(C) -fPIC $(CFLAGS) -c -o $@ $<

asm_%: %
	objdump -d -M intel $* > $(subst so,asm,$*)

main: main.c $(PROGS)
	gcc -L. -o $@ $< $(CFLAGS) $(LDFLAGS) -lzpoline -z now

########

.PHONY: download
download:
	cd data && wget https://up.zoolab.org/unixprog/hw01/examples.tgz && tar xf examples.tgz

.PHONY: test
test: all | test_ex1 test_ex2_1 test_ex2_2

.PHONY: test_ex1
test_ex1:
	LD_PRELOAD=libzpoline.so.1 ./examples/ex1 && echo "============="

.PHONY: test_ex2_1
test_ex2_1:
	LD_PRELOAD=libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}' && echo "============="

.PHONY: test_ex2_2
test_ex2_2:
	LD_PRELOAD=libzpoline.so.2 cat 'examples/ex2-2.txt' && echo "============="

.PHONY: asm
asm: $(addprefix asm_, $(PROGS))

.PHONY: debug
debug: CFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROGS) $(subst so,o,$(PROGS)) $(subst so,asm,$(PROGS)) main
