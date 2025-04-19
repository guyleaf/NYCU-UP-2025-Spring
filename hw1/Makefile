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

PROG			= libzpoline
SRCS			= libzpoline.c

# search dependencies
vpath %.c $(srcdir)

.PHONY: all
all: $(PROG).so

$(PROG).so: $(PROG).c
	$(C) -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $<

# main: main.c $(PROG).so
# 	gcc -L. -o $@ $< $(CFLAGS) $(LDFLAGS) -lzpoline -z now

########

.PHONY: download
download:
	cd data && wget https://up.zoolab.org/unixprog/hw01/examples.tgz && tar xf examples.tgz

.PHONY: test
test: | test_ex1

.PHONY: test_ex1
test_ex1:
	LD_PRELOAD=libzpoline.so ./examples/ex1

.PHONY: debug
debug: CFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROG).so main
