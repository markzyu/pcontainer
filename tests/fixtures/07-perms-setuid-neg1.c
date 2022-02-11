#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main() {
	int result;
	result = setuid(-1);
	printf("result: %d errno: %d\n", result, errno);
	return 0;
}
