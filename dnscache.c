#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "dnscache.h"
#include "dns.h"
#include "hash.h"

static const uint32_t initval = 0xdeaddead;

typedef struct cache_entry_t {
  struct cache_entry_t* prev;
  struct cache_entry_t* next;

  uint8_t addr[sizeof(struct in6_addr)];

  time_t expiration_time;

  uint8_t hostlen;
  char host[1];
} cache_entry_t;

static int dnscache_create(dnscache_t* cache, unsigned nbuckets);
static void dnscache_destroy(dnscache_t* cache);

static int dnscache_add(dnscache_t* cache,
                        const char* host,
                        size_t hostlen,
                        const void* addr,
                        socklen_t addrlen,
                        time_t expiration_time,
                        time_t now);

static int dnscache_get(dnscache_t* cache,
                        const char* host,
                        size_t hostlen,
                        time_t now,
                        void* addr,
                        socklen_t addrlen);

static void dnscache_remove_expired(dnscache_t* cache, time_t now);

static inline void cache_entry_push_front(node_t* header, cache_entry_t* entry)
{
  entry->next = (cache_entry_t*) (header->next);
  entry->prev = (cache_entry_t*) header;

  header->next->prev = (node_t*) entry;
  header->next = (node_t*) entry;
}

static inline void touch_cache_entry(node_t* header, cache_entry_t* entry)
{
  node_unlink((node_t*) entry);
  cache_entry_push_front(header, entry);
}

int dnscaches_create(dnscaches_t* caches, unsigned nbuckets)
{
  if (dnscache_create(&caches->ipv4, nbuckets) == 0) {
    if (dnscache_create(&caches->ipv6, nbuckets) == 0) {
      return 0;
    }

    dnscache_destroy(&caches->ipv4);
  }

  return -1;
}

void dnscaches_destroy(dnscaches_t* caches)
{
  dnscache_destroy(&caches->ipv4);
  dnscache_destroy(&caches->ipv6);
}

int dnscaches_add_ipv4(dnscaches_t* caches,
                       const char* host,
                       size_t hostlen,
                       const struct in_addr* addr,
                       time_t expiration_time,
                       time_t now)
{
  return dnscache_add(&caches->ipv4,
                      host,
                      hostlen,
                      addr,
                      4,
                      expiration_time,
                      now);
}

int dnscaches_add_ipv6(dnscaches_t* caches,
                       const char* host,
                       size_t hostlen,
                       const struct in6_addr* addr,
                       time_t expiration_time,
                       time_t now)
{
  return dnscache_add(&caches->ipv6,
                      host,
                      hostlen,
                      addr,
                      16,
                      expiration_time,
                      now);
}

int dnscaches_get_ipv4(dnscaches_t* caches,
                       const char* host,
                       size_t hostlen,
                       time_t now,
                       struct in_addr* addr)
{
  return dnscache_get(&caches->ipv4, host, hostlen, now, addr, 4);
}

int dnscaches_get_ipv6(dnscaches_t* caches,
                       const char* host,
                       size_t hostlen,
                       time_t now,
                       struct in6_addr* addr)
{
  return dnscache_get(&caches->ipv6, host, hostlen, now, addr, 16);
}

void dnscaches_remove_expired(dnscaches_t* caches, time_t now)
{
  dnscache_remove_expired(&caches->ipv4, now);
  dnscache_remove_expired(&caches->ipv6, now);
}

int dnscache_create(dnscache_t* cache, unsigned nbuckets)
{
  unsigned i;

  if ((cache->buckets = (node_t*) malloc(nbuckets * sizeof(node_t))) != NULL) {
    for (i = 0; i < nbuckets; i++) {
      cache->buckets[i].prev = &cache->buckets[i];
      cache->buckets[i].next = &cache->buckets[i];
    }

    cache->nbuckets = nbuckets;

    return 0;
  }

  return -1;
}

void dnscache_destroy(dnscache_t* cache)
{
  unsigned i;

  if (cache->buckets) {
    for (i = 0; i < cache->nbuckets; i++) {
      node_free_list(cache->buckets[i].next, &cache->buckets[i]);
    }

    free(cache->buckets);
    cache->buckets = NULL;
  }
}

int dnscache_add(dnscache_t* cache,
                 const char* host,
                 size_t hostlen,
                 const void* addr,
                 socklen_t addrlen,
                 time_t expiration_time,
                 time_t now)
{
  node_t* header;
  cache_entry_t* entry;
  cache_entry_t* next;

  if (hostlen <= HOSTNAME_MAX_LEN) {
    header = &cache->buckets[hash(host, hostlen, initval, cache->nbuckets)];
    entry = (cache_entry_t*) header->next;

    while (entry != (cache_entry_t*) header) {
      /* Same host?
       * (The caller is responsible for always using the same case, either
       *  lowercase or uppercase).
       */
      if ((hostlen == entry->hostlen) &&
          (memcmp(host, entry->host, hostlen) == 0)) {
        entry->expiration_time = expiration_time;

        touch_cache_entry(header, entry);

        return 0;
      }

      next = entry->next;

      /* If the entry has expired... */
      if (now > entry->expiration_time) {
        node_unlink((node_t*) entry);
        free(entry);
      }

      entry = next;
    }

    /* Create new entry. */
    if ((entry = (cache_entry_t*) malloc(offsetof(cache_entry_t, host) +
                                         hostlen + 1)) != NULL) {
      memcpy(entry->addr, addr, addrlen);

      entry->expiration_time = expiration_time;

      memcpy(entry->host, host, hostlen);
      entry->host[hostlen] = 0;

      entry->hostlen = hostlen;

      cache_entry_push_front(header, entry);

      return 0;
    }
  }

  return -1;
}

int dnscache_get(dnscache_t* cache,
                 const char* host,
                 size_t hostlen,
                 time_t now,
                 void* addr,
                 socklen_t addrlen)
{
  node_t* header;
  cache_entry_t* entry;
  cache_entry_t* next;

  if (hostlen <= HOSTNAME_MAX_LEN) {
    header = &cache->buckets[hash(host, hostlen, initval, cache->nbuckets)];
    entry = (cache_entry_t*) header->next;

    while (entry != (cache_entry_t*) header) {
      /* Same host?
       * (The caller is responsible for always using the same case, either
       *  lowercase or uppercase).
       */
      if ((hostlen == entry->hostlen) &&
          (memcmp(host, entry->host, hostlen) == 0)) {
        /* If the entry has not expired... */
        if (now <= entry->expiration_time) {
          /* Save address. */
          memcpy(addr, entry->addr, addrlen);

          touch_cache_entry(header, entry);

          return 0;
        } else {
          node_unlink((node_t*) entry);
          free(entry);

          return -1;
        }
      } else {
        next = entry->next;

        /* If the entry has expired... */
        if (now > entry->expiration_time) {
          node_unlink((node_t*) entry);
          free(entry);
        }

        entry = next;
      }
    }
  }

  return -1;
}

void dnscache_remove_expired(dnscache_t* cache, time_t now)
{
  node_t* header;
  cache_entry_t* entry;
  cache_entry_t* next;
  unsigned i;

  for (i = 0; i < cache->nbuckets; i++) {
    header = &cache->buckets[i];
    entry = (cache_entry_t*) header->next;

    while (entry != (cache_entry_t*) header) {
      next = entry->next;

      /* If the entry has expired... */
      if (now > entry->expiration_time) {
        node_unlink((node_t*) entry);
        free(entry);
      }

      entry = next;
    }
  }
}
