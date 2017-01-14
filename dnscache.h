#ifndef DNSCACHE_H
#define DNSCACHE_H

#include <time.h>
#include <netinet/in.h>
#include "node.h"

typedef struct {
  node_t* buckets;
  unsigned nbuckets;
} dnscache_t;

typedef struct {
  dnscache_t ipv4;
  dnscache_t ipv6;
} dnscaches_t;

int dnscaches_create(dnscaches_t* caches, unsigned nbuckets);
void dnscaches_destroy(dnscaches_t* caches);

int dnscaches_add_ipv4(dnscaches_t* caches,
                       const char* host,
                       size_t hostlen,
                       const struct in_addr* addr,
                       time_t expiration_time,
                       time_t now);

int dnscaches_add_ipv6(dnscaches_t* caches,
                       const char* host,
                       size_t hostlen,
                       const struct in6_addr* addr,
                       time_t expiration_time,
                       time_t now);

int dnscaches_get_ipv4(dnscaches_t* caches,
                       const char* host,
                       size_t hostlen,
                       time_t now,
                       struct in_addr* addr);

int dnscaches_get_ipv6(dnscaches_t* caches,
                       const char* host,
                       size_t hostlen,
                       time_t now,
                       struct in6_addr* addr);

void dnscaches_remove_expired(dnscaches_t* caches, time_t now);

#endif /* DNSCACHE_H */
