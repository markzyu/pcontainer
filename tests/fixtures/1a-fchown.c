#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
	int retval;
	int pid;
    char buffer[512];
       
    // Creation and chown
    FILE *f = fopen("/x", "w");
    if (f == NULL) return errno;
    retval = fchown(fileno(f), 0, 0);
    if (retval < 0) {
	    printf("fchown retval %d errno %d\n", retval, errno);
	    return errno;
    }
    fprintf(f, "TEST");
    fclose(f);

    // Double check whether owner is correct
    // Note: Android Termux libc does not support faccessat. So we must use fstatat
    struct stat stat_buf;
    retval = fstatat(AT_FDCWD, "/x", &stat_buf, AT_SYMLINK_NOFOLLOW);
    if (retval < 0) return errno;
    printf("fstatat(/x): owner = %d group = %d\n", stat_buf.st_uid, stat_buf.st_gid);

	return 0;
}
