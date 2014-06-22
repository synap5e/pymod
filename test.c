#include <stdio.h>
#include <unistd.h>

int foo(){
	return 42;
}

int main(){
	open(0xbadf00d, 0, 0);
	printf("%d\n", foo());
	return 0;
}
