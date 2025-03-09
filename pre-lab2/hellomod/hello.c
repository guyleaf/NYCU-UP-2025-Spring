#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEVFILE "/dev/hello_dev"

int main()
{
    int fd;
    char buf[64];
    if ((fd = open(DEVFILE, O_RDWR)) < 0)
    {
        perror("open");
        return -1;
    }

    read(fd, buf, sizeof(buf));
    write(fd, buf, sizeof(buf));
    ioctl(fd, 0x1234);
    ioctl(fd, 0x5678, 0xabcd);
    close(fd);

    return 0;
}
