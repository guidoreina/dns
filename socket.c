#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <errno.h>
#include "socket.h"

int build_socket_address(const char* str,
                         struct sockaddr_storage* addr,
                         socklen_t* addrlen)
{
  struct sockaddr_un* sun;
  const char* colon;
  const char* p;
  char host[64];
  unsigned port;
  size_t len;

  /* If not a Unix socket... */
  if (strchr(str, '/') == NULL) {
    /* Search the last colon (for IPv6 there might be more than one). */
    colon = NULL;
    p = str;
    while (*p) {
      if (*p == ':') {
        colon = p;
      }

      p++;
    }

    if ((colon) && (((len = colon - str)) > 0) && (len < sizeof(host))) {
      p = colon + 1;
      port = 0;
      while (*p) {
        if ((*p >= '0') &&
            (*p <= '9') &&
            ((port = (port * 10) + (*p - '0')) <= 65535)) {
          p++;
        } else {
          return -1;
        }
      }

      if (port > 0) {
        memcpy(host, str, len);
        host[len] = 0;

        return build_ip_address(host, port, addr, addrlen);
      }
    }
  } else {
    /* Unix socket. */
    sun = (struct sockaddr_un*) addr;

    if ((len = strlen(str)) < sizeof(sun->sun_path)) {
      sun->sun_family = AF_UNIX;

      memcpy(sun->sun_path, str, len);
      sun->sun_path[len] = 0;

      *addrlen = sizeof(struct sockaddr_un);

      return 0;
    }
  }

  return -1;
}

int build_ip_address(const char* str,
                     in_port_t port,
                     struct sockaddr_storage* addr,
                     socklen_t* addrlen)
{
  unsigned char buf[sizeof(struct in6_addr)];
  struct sockaddr_in* sin;
  struct sockaddr_in6* sin6;

  /* Try first with IPv4. */
  if (inet_pton(AF_INET, str, buf) > 0) {
    sin = (struct sockaddr_in*) addr;

    sin->sin_family = AF_INET;
    memcpy(&sin->sin_addr, buf, sizeof(struct in_addr));
    sin->sin_port = htons(port);
    memset(sin->sin_zero, 0, sizeof(sin->sin_zero));

    *addrlen = sizeof(struct sockaddr_in);
  } else if (inet_pton(AF_INET6, str, buf) > 0) {
    sin6 = (struct sockaddr_in6*) addr;

    memset(sin6, 0, sizeof(struct sockaddr_in6));

    sin6->sin6_family = AF_INET6;
    memcpy(&sin6->sin6_addr, buf, sizeof(struct in6_addr));
    sin6->sin6_port = htons(port);

    *addrlen = sizeof(struct sockaddr_in6);
  } else {
    return -1;
  }

  return 0;
}

int socket_connect(const struct sockaddr* addr, socklen_t addrlen)
{
  int fd;

  /* Create socket. */
  if ((fd = socket_create(addr->sa_family, SOCK_STREAM)) != -1) {
    /* Connect. */
    do {
      if (connect(fd, addr, addrlen) == 0) {
        return fd;
      }

      switch (errno) {
        case EINPROGRESS:
          return fd;
        case EINTR:
          continue;
        default:
          close(fd);
          return -1;
      }
    } while (1);
  }

  return -1;
}

int socket_get_error(int fd, int* error)
{
  socklen_t errorlen = sizeof(int);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, error, &errorlen) == 0) {
    return 0;
  }

  return -1;
}

int socket_listen(const struct sockaddr* addr, socklen_t addrlen)
{
  int fd;

  /* Create socket. */
  if ((fd = socket_create(addr->sa_family, SOCK_STREAM)) != -1) {
    /* Bind. */
    if (socket_bind(fd, addr, addrlen) == 0) {
      /* Listen. */
      if (listen(fd, SOMAXCONN) == 0) {
        return fd;
      }
    }

    close(fd);
  }

  return -1;
}

int socket_accept(int fd, struct sockaddr* addr, socklen_t* addrlen)
{
  int client;

  do {
    if ((client = accept4(fd, addr, addrlen, SOCK_NONBLOCK)) != -1) {
      return client;
    }
  } while (errno == EINTR);

  return -1;
}

ssize_t socket_recv(int fd, void* buf, size_t len)
{
  ssize_t ret;
  while (((ret = recv(fd, buf, len, 0)) < 0) && (errno == EINTR));
  return ret;
}

ssize_t socket_send(int fd, const void* buf, size_t len)
{
  ssize_t ret;
  while (((ret = send(fd, buf, len, MSG_NOSIGNAL)) < 0) && (errno == EINTR));
  return ret;
}

ssize_t socket_recvfrom(int fd,
                        void* buf,
                        size_t len,
                        struct sockaddr* addr,
                        socklen_t* addrlen)
{
  ssize_t ret;
  while (((ret = recvfrom(fd, buf, len, 0, addr, addrlen)) < 0) &&
         (errno == EINTR));

  return ret;
}

ssize_t socket_sendto(int fd,
                      const void* buf,
                      size_t len,
                      const struct sockaddr* addr,
                      socklen_t addrlen)
{
  ssize_t ret;
  while (((ret = sendto(fd, buf, len, MSG_NOSIGNAL, addr, addrlen)) < 0) &&
         (errno == EINTR));

  return ret;
}

int socket_recvmmsg(int fd,
                    struct mmsghdr* msgvec,
                    unsigned vlen,
                    struct timespec* timeout)
{
  int ret;
  while (((ret = recvmmsg(fd, msgvec, vlen, 0, timeout)) < 0) &&
         (errno == EINTR));

  return ret;
}

int socket_sendmmsg(int fd, struct mmsghdr* msgvec, unsigned vlen)
{
  int ret;
  while (((ret = syscall(__NR_sendmmsg, fd, msgvec, vlen, MSG_NOSIGNAL)) < 0) &&
         (errno == EINTR));

  return ret;
}

int socket_timed_connect(const struct sockaddr* addr,
                         socklen_t addrlen,
                         int timeout)
{
  int fd;
  int error;

  if ((fd = socket_connect(addr, addrlen)) != -1) {
    if (socket_wait_writable(fd, timeout) == 1) {
      if ((socket_get_error(fd, &error) == 0) && (error == 0)) {
        return fd;
      }
    }

    close(fd);
  }

  return -1;
}

/* Returns:
 *   -1: connection closed by peer or socket error
 *    0: timedout
 *    n: number of bytes received
 */
ssize_t socket_timed_recv(int fd, void* buf, size_t len, int timeout)
{
  ssize_t ret;

  switch (ret = socket_recv(fd, buf, len)) {
    default:
      return ret;
    case -1:
      if (errno == EAGAIN) {
        if (socket_wait_readable(fd, timeout) == 1) {
          if ((ret = socket_recv(fd, buf, len)) > 0) {
            return ret;
          } else {
            return -1;
          }
        } else {
          return 0;
        }
      }

      /* Fall through. */
    case 0:
      return -1;
  }
}

int socket_timed_recv_all(int fd, void* buf, size_t len, int timeout)
{
  uint8_t* b;
  ssize_t ret;

  b = (uint8_t*) buf;

  do {
    if ((ret = socket_recv(fd, b, len)) == (ssize_t) len) {
      return 0;
    }

    switch (ret) {
      default:
        if (socket_wait_readable(fd, timeout) == 1) {
          len -= ret;
          b += ret;
        } else {
          return -1;
        }

        break;
      case -1:
        if ((errno == EAGAIN) && (socket_wait_readable(fd, timeout) == 1)) {
          continue;
        }

        /* Fall through. */
      case 0:
        return -1;
    }
  } while (1);
}

ssize_t socket_timed_send(int fd, const void* buf, size_t len, int timeout)
{
  ssize_t ret;

  if ((ret = socket_send(fd, buf, len)) >= 0) {
    return ret;
  } else {
    if ((errno == EAGAIN) && (socket_wait_writable(fd, timeout) == 1)) {
      return socket_send(fd, buf, len);
    } else {
      return -1;
    }
  }
}

int socket_timed_send_all(int fd, const void* buf, size_t len, int timeout)
{
  const uint8_t* b;
  ssize_t ret;

  b = (const uint8_t*) buf;

  do {
    if ((ret = socket_send(fd, b, len)) == (ssize_t) len) {
      return 0;
    } else if (ret >= 0) {
      if (socket_wait_writable(fd, timeout) == 1) {
        len -= ret;
        b += ret;
      } else {
        return -1;
      }
    } else {
      if ((errno != EAGAIN) || (socket_wait_writable(fd, timeout) != 1)) {
        return -1;
      }
    }
  } while (1);
}

/* Returns:
 *   -2: socket error
 *   -1: timedout
 *    n: number of bytes received (it might be 0)
 */
ssize_t socket_timed_recvfrom(int fd,
                              void* buf,
                              size_t len,
                              struct sockaddr* addr,
                              socklen_t* addrlen,
                              int timeout)
{
  ssize_t ret;

  if ((ret = socket_recvfrom(fd, buf, len, addr, addrlen)) >= 0) {
    return ret;
  } else {
    if (errno == EAGAIN) {
      if (socket_wait_readable(fd, timeout) == 1) {
        if ((ret = socket_recvfrom(fd, buf, len, addr, addrlen)) >= 0) {
          return ret;
        }
      } else {
        return -1;
      }
    }

    return -2;
  }
}

ssize_t socket_timed_sendto(int fd,
                            const void* buf,
                            size_t len,
                            const struct sockaddr* addr,
                            socklen_t addrlen,
                            int timeout)
{
  ssize_t ret;

  if ((ret = socket_sendto(fd, buf, len, addr, addrlen)) >= 0) {
    return ret;
  } else {
    if ((errno == EAGAIN) && (socket_wait_writable(fd, timeout) == 1)) {
      return socket_sendto(fd, buf, len, addr, addrlen);
    } else {
      return -1;
    }
  }
}

int socket_create(int domain, int type)
{
  int fd;

  if ((fd = socket(domain, type, 0)) != -1) {
    if (socket_make_non_blocking(fd) == 0) {
      return fd;
    }

    close(fd);
  }

  return -1;
}

int socket_make_non_blocking(int fd)
{
#if USE_FIONBIO
  int value = 1;
  if (ioctl(fd, FIONBIO, &value) != -1) {
    return 0;
  }
#else
  int flags;

  if ((flags = fcntl(fd, F_GETFL)) != -1) {
    flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) != -1) {
      return 0;
    }
  }
#endif

  return -1;
}

int socket_bind(int fd, const struct sockaddr* addr, socklen_t addrlen)
{
  /* Reuse address. */
  int optval = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == 0) {
#ifdef SO_REUSEPORT
    /* Reuse port. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(int)) == 0) {
      return bind(fd, addr, addrlen);
    }
#else
    return bind(fd, addr, addrlen);
#endif
  }

  return -1;
}

int socket_wait_readable(int fd, int timeout)
{
  struct pollfd pollfd;

  pollfd.fd = fd;
  pollfd.events = POLLRDHUP | POLLIN;
  pollfd.revents = 0;

  return poll(&pollfd, 1, timeout);
}

int socket_wait_writable(int fd, int timeout)
{
  struct pollfd pollfd;

  pollfd.fd = fd;
  pollfd.events = POLLRDHUP | POLLOUT;
  pollfd.revents = 0;

  return poll(&pollfd, 1, timeout);
}
