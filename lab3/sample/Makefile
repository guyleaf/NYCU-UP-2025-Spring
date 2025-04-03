all: gotoku gotoku.local

libgotoku.so: libgotoku.c libgotoku.h
	gcc -shared -fPIC -o $@ $<

gotoku:
	curl -f -o $@ https://up.zoolab.org/unixprog/lab03/gotoku

gotoku.local: gotoku.c gops.c libgotoku.h libgotoku.so
	gcc -L. -o $@ gotoku.c -lgotoku -z now

clean:
	rm -f libgotoku.so gotoku gotoku.local
