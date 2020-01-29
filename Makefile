LIBFILE = asan-giovese.a

CC = gcc
CFLAGS = -ggdb

CFILES = alloc.c init.c poison.c report.c
HEADERS = asan-giovese.h

objects = $(CFILES:.c=.o)

all: lib

test: lib
	$(CC) $(CFLAGS) test.c $(LIBFILE) -o test.bin

.c.o:
	$(CC) $(CFLAGS) -I interval-tree -c $< -o $@ $(LDFLAGS)

lib: $(objects)
	$(AR) -crs $(LIBFILE) $(objects) 

$(objects): $(HEADERS)

clean:
	rm -fr $(objects) test.bin $(LIBFILE)
