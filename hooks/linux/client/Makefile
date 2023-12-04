CFLAGS=-I../lib

%.o: %.c $(DEPS)
	gcc -c -o $@ $< $(CFLAGS)

all: client getfd

getfd: getfd.o
	gcc -o $@ $^
client: client.o
	gcc -o $@ $^
clean:
	rm *.o client getfd