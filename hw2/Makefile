SHELL 			= /bin/sh

#### Start of system configuration section. ####

prefix 			= $(shell pwd)
srcdir			= $(prefix)
includesdir		= $(prefix)
examplesdir 	= $(prefix)/examples/hw2_testing_program
submissiondir	= ./311553007_hw2

CXX				= g++
CXXFLAGS		= -std=c++17 -Wall -Wextra -fPIE
LDFLAGS			= -lcapstone
LDPATHS			= $(examplesdir)

#### End of system configuration section. ####

PROGS			= sdb
SRCS			= program.cpp commands.cpp breakpoint.cpp ptools.cpp utils.cpp
INCLUDES		= $(SRCS:.cpp=.h) sdb.hpp auxv.h
OBJS			= $(SRCS:.cpp=.o)

# search dependencies
vpath %.cpp $(srcdir)
vpath %.h $(includesdir)

.PHONY: all
all: $(PROGS)

sdb: sdb.cpp $(OBJS) $(INCLUDES)
	$(CXX) -o $@ $< $(OBJS) $(CXXFLAGS) $(LDFLAGS)

%.o: %.cpp $(INCLUDES)
	$(CXX) -o $@ -c $< $(CXXFLAGS)

asm_%: %
	objdump -d -M intel $* > $*.asm

########

examples:
	mkdir -p /data/hw2/examples && ln -fs /data/hw2/examples
.PHONY: download
download: | examples
	cd examples && wget -O hw2_testing_program.zip https://up.zoolab.org/unixprog/hw02/hw2_testing_program.zip && unzip hw2_testing_program.zip

link_sdb:
	ln -sf $(prefix)/sdb $(examplesdir)
examples_%: | all link_sdb
	cd $(examplesdir) && ./sdb ./$*

# .PHONY: asm
# asm: $(addprefix asm_, $(PROGS))

.PHONY: debug
debug: CXXFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROGS) $(OBJS)

submission_dir:
	mkdir -p $(submissiondir)
.PHONY: submission
submission: | submission_dir
	cp *.h *.hpp *.cpp Makefile $(submissiondir) && tar cf 311553007_hw2.tgz $(submissiondir) && rm -rf $(submissiondir)
