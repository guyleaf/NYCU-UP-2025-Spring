all: gotoku.local

libgotoku.so: libgotoku.c libgotoku.h
	gcc -shared -fPIC -o $@ $<

gotoku.local: gotoku.c gops.c libgotoku.h libgotoku.so
	gcc -L. -Wl,-rpath=. -o $@ gotoku.c -lgotoku -z now

clean:
	rm -f libgotoku.so gotoku.local
