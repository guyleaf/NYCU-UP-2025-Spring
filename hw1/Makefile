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

########

.PHONY: debug
debug: CFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROG).so
