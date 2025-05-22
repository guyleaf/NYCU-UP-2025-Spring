SHELL 			= /bin/sh

#### Start of system configuration section. ####

CXX				= g++
CXXFLAGS		= -std=c++17 -Wall -Wextra -fPIE
LDFLAGS			= -lcapstone

prefix 			= .
srcdir			= $(prefix)
includesdir		= $(prefix)
examplesdir 	= $(prefix)/examples/hw2_testing_program
# toolsdir		= $(prefix)/tools

#### End of system configuration section. ####

PROGS			= sdb
SRCS			= ptools.cpp utils.cpp
INCLUDES		= $(SRCS:.cpp=.h) sdb.h
OBJS			= $(SRCS:.cpp=.o)

# search dependencies
vpath %.cpp $(srcdir)
vpath %.h $(includesdir)

.PHONY: all
all: $(PROGS)

sdb: sdb.cpp $(OBJS) $(INCLUDES)
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS)

%.o: %.cpp $(INCLUDES)
	$(CXX) -o $@ -c $< $(CXXFLAGS)

asm_%: %
	objdump -d -M intel $* > $*.asm

########

examples:
	mkdir -p /data/hw2/examples && ln -s /data/hw2/examples
.PHONY: download
download: | examples
	cd examples && wget -O hw2_testing_program.zip https://up.zoolab.org/unixprog/hw02/hw2_testing_program.zip && unzip hw2_testing_program.zip

# .PHONY: asm
# asm: $(addprefix asm_, $(PROGS))

.PHONY: debug
debug: CXXFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROGS) $(OBJS)
