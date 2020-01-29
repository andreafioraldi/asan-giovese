all:
	make -C interval-tree
	gcc -I interval-tree *.c interval-tree/rbtree.o -o test
