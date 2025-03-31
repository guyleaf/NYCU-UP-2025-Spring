SHELL 			= /bin/sh

#### Start of system configuration section. ####

CXX				= g++
CXXFLAGS		= -std=c++17 -Wall -Wextra -pedantic
LDFLAGS			=

prefix 			= .
srcdir			= $(prefix)
sampledir 	= $(prefix)/sample

#### End of system configuration section. ####

PROG			= libsolver
SRCS			= libsolver.c

# search dependencies
vpath %.c $(srcdir)

.PHONY: all
all: $(PROG).so

$(PROG).so: $(PROG).c libgotoku.h
	gcc -shared -fPIC -ldl -o $@ $<

########

.PHONY: sample
sample:
	make -C "$(sampledir)"

.PHONY: debug
debug: $(PROG).so sample

.PHONY: clean
clean:
	rm -f $(PROG).so

.PHONY: debug_clean
debug_clean: clean
	make -C "$(sampledir)" clean
