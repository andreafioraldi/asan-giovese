LIBFILE = asan-giovese.a

CC = gcc
CFLAGS = -ggdb

CFILES = asan-giovese.c
HEADERS = asan-giovese.h

objects = $(CFILES:.c=.o)

all: lib

test:
	$(CC) $(CFLAGS) test.c interval-tree/rbtree.c -o test.bin

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

lib: $(objects)
	make -C interval-tree
	$(AR) -crs $(LIBFILE) $(objects) interval-tree/rbtree.o 

$(objects): $(HEADERS)

clean:
	make -C interval-tree clean
	rm -fr $(objects) test.bin $(LIBFILE)
