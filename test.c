#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int foo(){
	return 42;
}

char* bar(){
	char* b = malloc(10);
	gets(b);
	return b;
}

char* baz = "World";

int main(){
	int i,y;
	open(0xbadf00d, 0, 0);
	printf("%d\n", foo());

	char *n = malloc(32);
	memcpy(n, "TESTTIME\x00", 9);
	n[3] = 'A';

	int spam[5];
	int *eggs = malloc(5);
	for (i=0;i<5;i++){
		spam[i] = i*100;
		eggs[i] = i*200;
	}
	int** peggs = &eggs;


	for(i=0;i<4;i++){
		char *b = bar();
		printf("%d, %s, %s\n", foo(), b, baz);
		for (y=0;y<5;y++)
			printf("%d, %d, ", spam[y], (*peggs)[y]);
		putchar('\n');
	}

	puts(n);


	return 0;
}
