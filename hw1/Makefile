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

PROGS			= libzpoline.so.1 libzpoline.so.2 libzpoline.so logger.so

# search dependencies
vpath %.c $(srcdir)

.PHONY: all
all: $(PROGS)

libzpoline.so: libzpoline.c
	$(C) -shared -fPIC -o $@ $< $(CFLAGS) $(LDFLAGS)

libzpoline.so.%: libzpoline%.c
	$(C) -shared -fPIC -o $@ $< $(CFLAGS) $(LDFLAGS)

# libzpoline.o: libzpoline.c
# 	$(C) -fPIC -c -o $@ $< $(CFLAGS)

# libzpoline.o.%: libzpoline%.c
# 	$(C) -fPIC -c -o $@ $< $(CFLAGS)

logger.so: logger.c
	$(C) -shared -fPIC -o $@ $< -std=gnu17 -Wall -Wextra

asm_%: %
	objdump -d -M intel $* > $(subst so,asm,$*)

########

.PHONY: download
download:
	mkdir -p /data/hw1/examples && ln -s /data/hw1/examples
download:
	cd examples && wget https://up.zoolab.org/unixprog/hw01/examples.tgz && tar xf examples.tgz

.PHONY: test
test: all | test_ex1 test_ex2_1 test_ex2_2 test_ex3 test_ex4_1 test_ex4_2 test_ex5 test_ex6

.PHONY: debug_test
debug_test: debug | test_ex1 test_ex2_1 test_ex2_2 test_ex3

.PHONY: test_ex1
test_ex1:
	LD_PRELOAD=libzpoline.so.1 ./examples/ex1 && echo "============="

.PHONY: test_ex2_1
test_ex2_1:
	LD_PRELOAD=libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}' && echo "============="

.PHONY: test_ex2_2
test_ex2_2:
	LD_PRELOAD=libzpoline.so.2 cat ./examples/ex2-2.txt && echo "============="

.PHONY: test_ex3
test_ex3:
	LD_PRELOAD=libzpoline.so LIBZPHOOK=./examples/libex3hook.so ./examples/ex3  && echo "============="

.PHONY: test_ex4_1
test_ex4_1:
	LD_PRELOAD=libzpoline.so LIBZPHOOK=logger.so touch main.c && rm main.c && echo "============="

.PHONY: test_ex4_2
test_ex4_2:
	LD_PRELOAD=libzpoline.so LIBZPHOOK=logger.so cat /etc/hosts && echo "============="

.PHONY: test_ex5
test_ex5:
	LD_PRELOAD=libzpoline.so LIBZPHOOK=logger.so wget http://www.google.com -q -t 1 && echo "============="

.PHONY: test_ex6
test_ex6:
	LD_PRELOAD=libzpoline.so LIBZPHOOK=logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")' && echo "============="

.PHONY: asm
asm: $(addprefix asm_, $(PROGS))

.PHONY: debug
debug: CFLAGS += -DDEBUG -g -Og
debug: all

.PHONY: clean
clean:
	rm -f $(PROGS) $(subst so,o,$(PROGS)) $(subst so,asm,$(PROGS)) index.html*
