#include <stdio.h>
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
	open(0xbadf00d, 0, 0);
	printf("%d\n", foo());

	char *n = malloc(32);
	memcpy(n, "TESTTIME\x00", 9);
	n[3] = 'A';

	int i;
	for(i=0;i<2;i++){
		char *b = bar();
		printf("%d, %s, %s\n", foo(), b, baz);
		free(b);
	}

	puts(n);

	return 0;
}
