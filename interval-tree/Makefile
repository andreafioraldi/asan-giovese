VER=0.10-dev
RELEASE=v$(VER)

CC = gcc
CFLAGS = -Wall -ggdb -D_FILE_OFFSET_BITS=64

CFILES=rbtree.c
HEADERS=interval_tree_generic.h rbtree_augmented.h  rbtree.h

objects = $(CFILES:.c=.o)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBRARY_FLAGS)

all: $(objects)
$(objects): $(HEADERS)

clean:
	rm -fr $(objects)
