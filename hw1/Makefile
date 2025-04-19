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
	$(C) -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $<

libzpoline.so.1: libzpoline1.c
	$(C) -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $<

libzpoline.so.2: libzpoline2.c
	$(C) -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $<

main: main.c $(PROGS)
	gcc -L. -o $@ $< $(CFLAGS) $(LDFLAGS) -lzpoline -z now

########

.PHONY: download
download:
	cd data && wget https://up.zoolab.org/unixprog/hw01/examples.tgz && tar xf examples.tgz

.PHONY: test
test: | test_ex1

.PHONY: test_ex1
test_ex1:
	LD_PRELOAD=libzpoline.so.2 ./examples/ex1

.PHONY: debug
debug: CFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROGS) main
