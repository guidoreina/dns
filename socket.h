#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>
#include <netinet/in.h>

int build_socket_address(const char* str,
                         struct sockaddr_storage* addr,
                         socklen_t* addrlen);

int build_ip_address(const char* str,
                     in_port_t port,
                     struct sockaddr_storage* addr,
                     socklen_t* addrlen);

int socket_connect(const struct sockaddr* addr, socklen_t addrlen);
int socket_get_error(int fd, int* error);
int socket_listen(const struct sockaddr* addr, socklen_t addrlen);
int socket_accept(int fd, struct sockaddr* addr, socklen_t* addrlen);
ssize_t socket_recv(int fd, void* buf, size_t len);
ssize_t socket_send(int fd, const void* buf, size_t len);
ssize_t socket_recvfrom(int fd,
                        void* buf,
                        size_t len,
                        struct sockaddr* addr,
                        socklen_t* addrlen);

ssize_t socket_sendto(int fd,
                      const void* buf,
                      size_t len,
                      const struct sockaddr* addr,
                      socklen_t addrlen);

int socket_recvmmsg(int fd,
                    struct mmsghdr* msgvec,
                    unsigned vlen,
                    struct timespec* timeout);

int socket_sendmmsg(int fd, struct mmsghdr* msgvec, unsigned vlen);

int socket_timed_connect(const struct sockaddr* addr,
                         socklen_t addrlen,
                         int timeout);

ssize_t socket_timed_recv(int fd, void* buf, size_t len, int timeout);
int socket_timed_recv_all(int fd, void* buf, size_t len, int timeout);
ssize_t socket_timed_send(int fd, const void* buf, size_t len, int timeout);
int socket_timed_send_all(int fd, const void* buf, size_t len, int timeout);
ssize_t socket_timed_recvfrom(int fd,
                              void* buf,
                              size_t len,
                              struct sockaddr* addr,
                              socklen_t* addrlen,
                              int timeout);

ssize_t socket_timed_sendto(int fd,
                            const void* buf,
                            size_t len,
                            const struct sockaddr* addr,
                            socklen_t addrlen,
                            int timeout);

int socket_create(int domain, int type);
int socket_make_non_blocking(int fd);
int socket_bind(int fd, const struct sockaddr* addr, socklen_t addrlen);
int socket_wait_readable(int fd, int timeout);
int socket_wait_writable(int fd, int timeout);

#endif /* SOCKET_H */
