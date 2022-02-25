
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int value = 0;

int main() {
	int result;
    FILE* f;
    int count;
    char line[2048];

    value = 0;

    result = vfork();
    if (result < 0) {
        printf("result: %d errno: %d\n", result, errno);
    } else if (result == 0) {
        sleep(1);
        value = 22;

        // Make sure we are being traced.
        f = fopen("/proc/self/status", "r");
        count = 0;
        if (f != NULL) {
            while(fgets(line, sizeof line, f) != NULL) {
                if (count == 7) {
                    printf("%s\n", line);
                    break;
                }
                count ++;
            }
        }
        exit(0);
    } else {
        printf("result: %d errno: %d\n", value, errno);
    }
	return 0;
}
