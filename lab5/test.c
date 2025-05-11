#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONCURRENT 1000
#define _WEB_ROOT "wwwroot"
#define _REQ_PASSLEN 128

static char *__load_file_internal(int fd, int sz)
{
    int rlen;
    char *wptr, *content = NULL;
    if ((wptr = content = (char *)malloc(sz)) == NULL) goto quit;
    while ((rlen = read(fd, wptr, sz)) > 0)
    {
        printf("Read\n");
        wptr += rlen;
        sz -= rlen;
    }
quit:
    close(fd);
    return content;
}

int main(void)
{
    unsigned long seed = 156183;
    unsigned long long x2 = seed * 6364136223846793005ULL + 1;
    x2 >>= 33;
    printf("%lu\n", x2);

    int fd, sz;
    struct stat st;
    const char fname[] = "/workspaces";
    if ((fd = open(fname, O_RDONLY)) < 0) exit(EXIT_FAILURE);
    if (stat(fname, &st) < 0) exit(EXIT_FAILURE);
    sz = st.st_size;

    char *content = __load_file_internal(fd, sz);
    printf("%d, %s\n", sz, content);
    free(content);

    char rpath[PATH_MAX];
    realpath("wwwroot//.", rpath);
    printf("%s\n", rpath);

    return 0;
}
