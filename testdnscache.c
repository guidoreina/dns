#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include "dnscache.h"

#define NUMBER_BUCKETS     127
#define NUMBER_IPS         (5 * 1000)
#define NUMBER_REPETITIONS 3

int main()
{
  dnscaches_t caches;
  struct in_addr addr;
  char host[256];
  size_t hostlen;
  time_t now;
  unsigned i;
  unsigned j;

  /* Create caches. */
  if (dnscaches_create(&caches, NUMBER_BUCKETS) < 0) {
    fprintf(stderr, "Error creating caches.\n");
    return -1;
  }

  for (i = 0; i < NUMBER_REPETITIONS; i++) {
    now = 0;

    /* Add to DNS cache. */
    for (j = 0; j < NUMBER_IPS; j++) {
      hostlen = snprintf(host, sizeof(host), "www.%06u.net", j);
      addr.s_addr = j + 1;

      if (dnscaches_add_ipv4(&caches, host, hostlen, &addr, now + 1, now) < 0) {
        fprintf(stderr, "Error adding '%s' to DNS cache.\n", host);

        dnscaches_destroy(&caches);
        return -1;
      }
    }

    now++;

    /* Search. */
    for (j = 0; j < NUMBER_IPS; j++) {
      hostlen = snprintf(host, sizeof(host), "www.%06u.net", j);

      if (dnscaches_get_ipv4(&caches, host, hostlen, now, &addr) < 0) {
        fprintf(stderr, "Error getting '%s' from DNS cache.\n", host);

        dnscaches_destroy(&caches);
        return -1;
      }

      if (addr.s_addr != j + 1) {
        fprintf(stderr,
                "IP addresses for host '%s' don't match (found: %u, "
                "expected: %u).\n",
                host,
                addr.s_addr,
                j + 1);

        dnscaches_destroy(&caches);
        return -1;
      }
    }

    now++;

    /* Search. */
    for (j = NUMBER_IPS; j > 0; j--) {
      hostlen = snprintf(host, sizeof(host), "www.%06u.net", j - 1);

      if (dnscaches_get_ipv4(&caches, host, hostlen, now, &addr) == 0) {
        fprintf(stderr,
                "Found IP address for host '%s' when not expected.\n",
                host);

        dnscaches_destroy(&caches);
        return -1;
      }
    }

    dnscaches_remove_expired(&caches, now);

    now = 0;

    /* Add to DNS cache. */
    for (j = 0; j < NUMBER_IPS; j++) {
      hostlen = snprintf(host, sizeof(host), "www.%06u.net", j);
      addr.s_addr = j + 1;

      if (dnscaches_add_ipv4(&caches, host, hostlen, &addr, now + 1, now) < 0) {
        fprintf(stderr, "Error adding '%s' to DNS cache.\n", host);

        dnscaches_destroy(&caches);
        return -1;
      }
    }

    now++;

    dnscaches_remove_expired(&caches, now);

    /* Search. */
    for (j = 0; j < NUMBER_IPS; j++) {
      hostlen = snprintf(host, sizeof(host), "www.%06u.net", j);

      if (dnscaches_get_ipv4(&caches, host, hostlen, now, &addr) < 0) {
        fprintf(stderr, "Error getting '%s' from DNS cache.\n", host);

        dnscaches_destroy(&caches);
        return -1;
      }

      if (addr.s_addr != j + 1) {
        fprintf(stderr,
                "IP addresses for host '%s' don't match (found: %u, "
                "expected: %u).\n",
                host,
                addr.s_addr,
                j + 1);

        dnscaches_destroy(&caches);
        return -1;
      }
    }

    now++;

    dnscaches_remove_expired(&caches, now);

    /* Search. */
    for (j = NUMBER_IPS; j > 0; j--) {
      hostlen = snprintf(host, sizeof(host), "www.%06u.net", j - 1);

      if (dnscaches_get_ipv4(&caches, host, hostlen, now, &addr) == 0) {
        fprintf(stderr,
                "Found IP address for host '%s' when not expected.\n",
                host);

        dnscaches_destroy(&caches);
        return -1;
      }
    }
  }

  /* Add to DNS cache. */
  for (j = 0; j < NUMBER_IPS; j++) {
    hostlen = snprintf(host, sizeof(host), "www.%06u.net", j);
    addr.s_addr = j + 1;

    if (dnscaches_add_ipv4(&caches, host, hostlen, &addr, now + 1, now) < 0) {
      fprintf(stderr, "Error adding '%s' to DNS cache.\n", host);

      dnscaches_destroy(&caches);
      return -1;
    }
  }

  dnscaches_destroy(&caches);

  return 0;
}
