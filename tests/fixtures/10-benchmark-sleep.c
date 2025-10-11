#include <errno.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int value = 0;

int main() {
    int count;
    struct timespec start_time, end_time;

    count = 0;

    clock_gettime(CLOCK_MONOTONIC, &start_time);
    while (count < 1000) {
	    sleep(0);
	    count ++;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    long long elapsed_ns = (long long)(end_time.tv_sec - start_time.tv_sec) * 1000000000LL +
                           (end_time.tv_nsec - start_time.tv_nsec);
    printf("Elapsed time: %lld nanoseconds\n", elapsed_ns);
    
    return 0;
}
