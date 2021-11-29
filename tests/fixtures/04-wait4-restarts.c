#include <errno.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>

int main() {
	int wstatus = 0;
	int retval;
	int pid;
       
	retval = fork();
	if (retval <= 0) {
		sleep(1);
		return 1;
	}

	pid = retval;
	retval = waitpid(pid, &wstatus, WNOHANG | WUNTRACED);
	if (retval < 0) printf("waitpid failure: %d\n", errno);
	printf("is exit: %d is stop: %d exit code: %d\n", WIFEXITED(wstatus), WIFSTOPPED(wstatus), WEXITSTATUS(wstatus));

	sleep(2);

	retval = waitpid(pid, &wstatus, WNOHANG | WUNTRACED);
	if (retval < 0) printf("waitpid failure: %d\n", errno);
	printf("is exit: %d is stop: %d exit code: %d\n", WIFEXITED(wstatus), WIFSTOPPED(wstatus), WEXITSTATUS(wstatus));

	return 0;
}
