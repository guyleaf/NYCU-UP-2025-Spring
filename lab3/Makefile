SHELL 			= /bin/sh

#### Start of system configuration section. ####

C				= gcc
CFLAGS			= -std=c17 -Wall -Wextra -pedantic
LDFLAGS			= -ldl

prefix 			= .
srcdir			= $(prefix)
sampledir 		= $(prefix)/sample
toolsdir		= $(prefix)/tools

#### End of system configuration section. ####

PROG			= libgotoku
SRCS			= libgotoku.c

# search dependencies
vpath %.c $(srcdir)

.PHONY: all
all: $(PROG).so

got_gotoku.h: sample
	python3 "$(toolsdir)/generate_got_header.py" "$(sampledir)/gotoku" -o $@

got_gotoku_local.h: sample
	python3 "$(toolsdir)/generate_got_header.py" "$(sampledir)/gotoku.local" -o $@

$(PROG).so: $(PROG).c libgotoku.h got_gotoku.h got_gotoku_local.h
	$(C) -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $<

########

.PHONY: sample
sample:
	make -C "$(sampledir)"

.PHONY: debug
debug: CFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROG).so got_gotoku.h got_gotoku_local.h

.PHONY: sample_clean
sample_clean:
	make -C "$(sampledir)" clean
