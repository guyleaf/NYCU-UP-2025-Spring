SHELL 			= /bin/sh

#### Start of system configuration section. ####

C				= gcc
CFLAGS			= -std=c17 -Wall -Wextra
LDFLAGS			= -ldl

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

libzpoline.so: libzpoline.c
	$(C) -nostartfiles -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $<

libzpoline.so.1: libzpoline1.c
	$(C) -nostartfiles -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $<

libzpoline.so.2: libzpoline2.c
	$(C) -nostartfiles -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $<

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

.PHONY: debug
debug: CFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROGS) main
