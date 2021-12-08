#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
	int retval;
	int pid;
    char buffer[512];
       
    // Creation
    FILE *f = fopen("/x", "w");
    if (f == NULL) return errno;
    fprintf(f, "TEST");
    fclose(f);

    retval = symlink("/x", "/y");
    if (retval < 0) return errno;
    retval = symlink("/link", "/link");
    if (retval < 0) return errno;
    retval = symlink("/a", "/b");
    if (retval < 0) return errno;
    retval = symlink("/b", "/c");
    if (retval < 0) return errno;
    retval = symlink("/c", "/a");
    if (retval < 0) return errno;

    printf("created symlinks\n");

    // Read
    memset(buffer, 0, 512);
    retval = readlink("/link", buffer, 512);
    if (retval < 0) return errno;
    printf("/link -> %s\n", buffer);

    memset(buffer, 0, 512);
    retval = readlink("/a", buffer, 512);
    if (retval < 0) return errno;
    printf("/a -> %s\n", buffer);

    memset(buffer, 0, 512);
    retval = readlink("/y", buffer, 512);
    if (retval < 0) return errno;
    printf("/y -> %s\n", buffer);

    retval = readlink("/x", buffer, 512);
    printf("readlink(/x) = %d errno = %d \n", retval, errno);

    retval = open("/link", O_RDONLY);
    printf("open(/link) = %d errno = %d\n", retval >= 0 ? 0 : retval, errno);
    retval = open("/a", O_RDONLY);
    printf("open(/a) = %d errno = %d\n", retval >= 0 ? 0 : retval, errno);
    retval = open("/y", O_RDONLY);
    printf("open(/y) = %d errno = %d\n", retval >= 0 ? 0 : retval, errno);
    retval = open("/x", O_RDONLY);
    printf("open(/x) = %d errno = %d\n", retval >= 0 ? 0 : retval, errno);

    // Rename
    retval = rename("/y", "/z");
    if (retval < 0) return errno;

    memset(buffer, 0, 512);
    retval = readlink("/z", buffer, 512);
    if (retval < 0) return errno;
    printf("/z -> %s\n", buffer);

    // Delete
    retval = unlink("/link");
    if (retval < 0) return errno;
    retval = unlink("/a");
    if (retval < 0) return errno;
    retval = unlink("/b");
    if (retval < 0) return errno;
    retval = unlink("/c");
    if (retval < 0) return errno;
    retval = unlink("/z");
    if (retval < 0) return errno;

    // Double check whether links still exist
    retval = faccessat(AT_FDCWD, "/link", R_OK, AT_SYMLINK_NOFOLLOW);
    printf("access(/link) = %d errno = %d\n", retval, errno);
    retval = faccessat(AT_FDCWD, "/a", R_OK, AT_SYMLINK_NOFOLLOW);
    printf("access(/a) = %d errno = %d\n", retval, errno);
    retval = faccessat(AT_FDCWD, "/b", R_OK, AT_SYMLINK_NOFOLLOW);
    printf("access(/b) = %d errno = %d\n", retval, errno);
    retval = faccessat(AT_FDCWD, "/c", R_OK, AT_SYMLINK_NOFOLLOW);
    printf("access(/c) = %d errno = %d\n", retval, errno);
    retval = faccessat(AT_FDCWD, "/y", R_OK, AT_SYMLINK_NOFOLLOW);
    printf("access(/y) = %d errno = %d\n", retval, errno);
    retval = faccessat(AT_FDCWD, "/x", R_OK, AT_SYMLINK_NOFOLLOW);
    printf("access(/x) = %d errno = %d\n", retval, errno);
    retval = faccessat(AT_FDCWD, "/z", R_OK, AT_SYMLINK_NOFOLLOW);
    printf("access(/z) = %d errno = %d\n", retval, errno);

	return 0;
}
