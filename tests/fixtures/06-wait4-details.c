// NOTE: Only run this program using a multithreaded tracer. Otherwise, the outputs will differ.

#include <errno.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>

int main() {
	int wstatus;
	int retval;
	int pid;
       
    // Case# 1, with WNOHANG (retval should be 0, hinting to retry)
	retval = fork();
	if (retval <= 0) {
		sleep(1);
		return 1;
	}

	pid = retval;
    wstatus = 0;
	retval = waitpid(pid, &wstatus, WNOHANG | WUNTRACED);
    printf("case1, retval %d, status %d\n", retval, wstatus);
       
    // Case# 2, without WNOHANG (retval should be -EINTR, hinting to retry)
    sleep(2);
	retval = fork();
	if (retval <= 0) {
		sleep(1);
		return 1;
	}

	pid = retval;
    wstatus = 0;
	retval = waitpid(pid, &wstatus, WUNTRACED);
    printf("case2, retval %d, errno %d, status %d\n", retval, errno, wstatus);
       
    // Case# 3, without WUNTRACED (retval should be PID, wstatus should be EXITED)
    sleep(2);
	retval = fork();
	if (retval <= 0) {
		sleep(1);
		return 1;
	}

	pid = retval;
    wstatus = 0;
	retval = waitpid(pid, &wstatus, 0);
    if (retval == pid) {
        printf("case3, retval pid, status %d\n", wstatus);
    } else {
        printf("case3, retval %d, status %d\n", retval, wstatus);
    }

	return 0;
}
