#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define NUM_SYSCALLS 548
#define LOG_PFX "[logger] "

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t);
typedef void (*log_fn_t)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t,
                         int64_t, int64_t);

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall);
static void __log_read(int64_t fd, int64_t buf, int64_t count, int64_t r10,
                       int64_t r8, int64_t r9, int64_t rax, int64_t ret);
static void __log_write(int64_t fd, int64_t buf, int64_t count, int64_t r10,
                        int64_t r8, int64_t r9, int64_t rax, int64_t ret);
static void __log_connect(int64_t sockfd, int64_t addr, int64_t addrlen,
                          int64_t r10, int64_t r8, int64_t r9, int64_t rax,
                          int64_t ret);
static void __log_execve(int64_t pathname, int64_t argv, int64_t envp,
                         int64_t r10, int64_t r8, int64_t r9, int64_t rax,
                         int64_t ret);
static void __log_openat(int64_t dirfd, int64_t file, int64_t flags,
                         int64_t mode, int64_t r8, int64_t r9, int64_t rax,
                         int64_t ret);
static void __log_clone(int64_t fn, int64_t stack, int64_t flags, int64_t r10,
                        int64_t r8, int64_t r9, int64_t rax, int64_t ret);
static void __log_clone3(int64_t cl_args, int64_t size, int64_t rdx,
                         int64_t r10, int64_t r8, int64_t r9, int64_t rax,
                         int64_t ret);

static syscall_hook_fn_t original_syscall = NULL;
static log_fn_t logger_map[NUM_SYSCALLS];
static bool logging_pos[NUM_SYSCALLS];

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t r10, int64_t r8, int64_t r9, int64_t rax)
{
    int64_t ret = 0;
    log_fn_t log_fn;
    if (rax < NUM_SYSCALLS && (log_fn = logger_map[rax]) != NULL)
    {
        if (!logging_pos[rax])
        {
            log_fn(rdi, rsi, rdx, r10, r8, r9, rax, ret);
        }
        ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
        if (logging_pos[rax])
        {
            log_fn(rdi, rsi, rdx, r10, r8, r9, rax, ret);
        }
    }
    else
    {
        ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);
    }
    return ret;
}

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall)
{
    original_syscall = trigger_syscall;
    *hooked_syscall = syscall_hook_fn;
    memset(logger_map, 0, sizeof(logger_map));
    memset(logging_pos, true, sizeof(logging_pos));
    logger_map[SYS_read] = __log_read;
    logger_map[SYS_write] = __log_write;
    logger_map[SYS_connect] = __log_connect;
    logger_map[SYS_execve] = __log_execve;
    logging_pos[SYS_execve] = false;
    logger_map[SYS_openat] = __log_openat;
    logger_map[SYS_clone] = __log_clone;
    logging_pos[SYS_clone] = false;
    logger_map[SYS_clone3] = __log_clone3;
    logging_pos[SYS_clone3] = false;
}

static void __log_rw(const char *fname, int fd, uint8_t *buf, size_t count,
                     ssize_t ret, size_t output_size)
{
    size_t __output_size = output_size > 32 ? 32 : output_size;
    fprintf(stderr, LOG_PFX "%s(%d, \"", fname, (int)fd);
    for (size_t i = 0; i < __output_size; i++)
    {
        uint8_t byte = buf[i];
        if (isprint(byte) || isspace(byte))
        {
            switch (byte)
            {
                case '\t':
                    fprintf(stderr, "\\t");
                    break;
                case '\n':
                    fprintf(stderr, "\\n");
                    break;
                case '\r':
                    fprintf(stderr, "\\r");
                    break;
                default:
                    fprintf(stderr, "%c", (char)byte);
                    break;
            }
        }
        else
        {
            // print non-pritable bytes in hex format
            fprintf(stderr, "\\x%02hhx", byte);
        }
    }
    fprintf(stderr, "\"");
    if (output_size > 32)
    {
        fprintf(stderr, "...");
    }
    fprintf(stderr, ", %lu) = %ld\n", count, ret);
}

static void __log_read(int64_t fd, int64_t buf, int64_t count,
                       __attribute__((unused)) int64_t r10,
                       __attribute__((unused)) int64_t r8,
                       __attribute__((unused)) int64_t r9,
                       __attribute__((unused)) int64_t rax, int64_t ret)
{
    ssize_t ret_size = (ssize_t)ret;
    size_t output_size = ret_size > 0 ? (size_t)ret_size : 0;
    __log_rw("read", (int)fd, (uint8_t *)buf, (size_t)count, ret_size,
             output_size);
}

static void __log_write(int64_t fd, int64_t buf, int64_t count,
                        __attribute__((unused)) int64_t r10,
                        __attribute__((unused)) int64_t r8,
                        __attribute__((unused)) int64_t r9,
                        __attribute__((unused)) int64_t rax, int64_t ret)
{
    __log_rw("write", (int)fd, (uint8_t *)buf, (size_t)count, (ssize_t)ret,
             (size_t)count);
}

static void __log_connect(int64_t sockfd, int64_t addr, int64_t addrlen,
                          __attribute__((unused)) int64_t r10,
                          __attribute__((unused)) int64_t r8,
                          __attribute__((unused)) int64_t r9,
                          __attribute__((unused)) int64_t rax, int64_t ret)
{
    int fd = (int)sockfd;
    const struct sockaddr *sock_addr = (struct sockaddr *)addr;
    socklen_t sock_len = (socklen_t)addrlen;

    fprintf(stderr, LOG_PFX "connect(%d, \"", fd);
    switch (sock_addr->sa_family)
    {
        case AF_UNIX:
        {
            const struct sockaddr_un *unix_sock_addr =
                (const struct sockaddr_un *)sock_addr;
            fprintf(stderr, "UNIX:%s", unix_sock_addr->sun_path);
            break;
        }
        case AF_INET:
        case AF_INET6:
        {
            in_port_t port;
            if (sock_addr->sa_family == AF_INET)
            {
                const struct sockaddr_in *in_sock_addr =
                    (const struct sockaddr_in *)sock_addr;
                port = in_sock_addr->sin_port;
            }
            else
            {
                const struct sockaddr_in6 *in6_sock_addr =
                    (const struct sockaddr_in6 *)sock_addr;
                port = in6_sock_addr->sin6_port;
            }

            char buf[INET6_ADDRSTRLEN];
            inet_ntop(sock_addr->sa_family, sock_addr, buf, addrlen);
            fprintf(stderr, "%s:%hu", buf, port);
            break;
        }
        default:
            return;
    }
    fprintf(stderr, "\", %u) = %d\n", sock_len, (int)ret);
}

static void __log_execve(int64_t pathname, int64_t argv, int64_t envp,
                         __attribute__((unused)) int64_t r10,
                         __attribute__((unused)) int64_t r8,
                         __attribute__((unused)) int64_t r9,
                         __attribute__((unused)) int64_t rax,
                         __attribute__((unused)) int64_t ret)
{
    fprintf(stderr, LOG_PFX "execve(\"%s\", %p, %p)\n", (const char *)pathname,
            (char *const)argv, (char *const)envp);
}

static void __log_openat(int64_t dirfd, int64_t file, int64_t flags,
                         int64_t mode, __attribute__((unused)) int64_t r8,
                         __attribute__((unused)) int64_t r9,
                         __attribute__((unused)) int64_t rax, int64_t ret)
{
    char fd_buf[50] = "AT_FDCWD";
    int fd = (int)dirfd;
    if (fd != AT_FDCWD)
    {
        snprintf(fd_buf, sizeof(fd_buf), "%d", fd);
    }

    fprintf(stderr, LOG_PFX "openat(%s, \"%s\", %#x, %#o) = %d\n", fd_buf,
            (char *)file, (int)flags, (mode_t)mode, (int)ret);
}

static void __log_clone(int64_t fn, int64_t stack, int64_t flags,
                        __attribute__((unused)) int64_t r10,
                        __attribute__((unused)) int64_t r8,
                        __attribute__((unused)) int64_t r9,
                        __attribute__((unused)) int64_t rax, int64_t ret)
{
    fprintf(stderr, LOG_PFX "clone(%p, %p, %d) = %d\n", (void *)fn,
            (void *)stack, (int)flags, (int)ret);
}

static void __log_clone3(int64_t cl_args, int64_t size,
                         __attribute__((unused)) int64_t rdx,
                         __attribute__((unused)) int64_t r10,
                         __attribute__((unused)) int64_t r8,
                         __attribute__((unused)) int64_t r9,
                         __attribute__((unused)) int64_t rax, int64_t ret)
{
    fprintf(stderr, LOG_PFX "clone3(%p, %lu) = %ld\n", (void *)cl_args,
            (size_t)size, (long)ret);
}
