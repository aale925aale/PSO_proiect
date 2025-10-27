CC := gcc
CFLAGS := -Wall
objs := server.o myqueue.o

all: server

server: $(objs)
	$(CC) $(CFLAGS) $(objs) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o