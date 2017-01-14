#include <stdlib.h>
#include "hash.h"

/* http://burtleburtle.net/bob/hash/doobs.html */
#define mix(a, b, c)                      \
        {                                 \
          a -= b; a -= c; a ^= (c >> 13); \
          b -= c; b -= a; b ^= (a << 8);  \
          c -= a; c -= b; c ^= (b >> 13); \
          a -= b; a -= c; a ^= (c >> 12); \
          b -= c; b -= a; b ^= (a << 16); \
          c -= a; c -= b; c ^= (b >> 5);  \
          a -= b; a -= c; a ^= (c >> 3);  \
          b -= c; b -= a; b ^= (a << 10); \
          c -= a; c -= b; c ^= (b >> 15); \
        }

uint32_t hash4(const void* data, uint32_t max)
{
  uint32_t a;

  a = *((uint32_t*) data);

  /* http://burtleburtle.net/bob/hash/integer.html */
  a = a ^ (a >> 4);
  a = (a ^ 0xdeadbeef) + (a << 5);

  return ((a ^ (a >> 11)) % max);
}

uint32_t hash16(const void* data, uint32_t initval, uint32_t max)
{
  /* http://burtleburtle.net/bob/hash/doobs.html */

  const uint8_t* k;
  uint32_t a, b, c;

  k = (const uint8_t*) data;

  /* Set up the internal state. */
  a = b = 0x9e3779b9; /* The golden ratio; an arbitrary value. */
  c = initval; /* The previous hash value. */

  /*--------------------------------------- Handle most of the key. */
  a += (k[0] +
        ((uint32_t) k[1] << 8) +
        ((uint32_t) k[2] << 16) +
        ((uint32_t) k[3] << 24));

  b += (k[4] +
        ((uint32_t) k[5] << 8) +
        ((uint32_t) k[6] << 16) +
        ((uint32_t) k[7] << 24));

  c += (k[8] +
        ((uint32_t) k[9] << 8) +
        ((uint32_t) k[10] << 16) +
        ((uint32_t) k[11] << 24));

  mix(a, b, c);

  /*-------------------------------------- Handle the last 4 bytes. */
  a += (((uint32_t) k[15] << 24) +
        ((uint32_t) k[14] << 16) +
        ((uint32_t) k[13] << 8) +
        k[12]);

  c += 16;
  mix(a, b, c);

  /*-------------------------------------------- Report the result. */
  return (c % max);
}

uint32_t hash(const void* data, size_t length, uint32_t initval, uint32_t max)
{
  /* http://burtleburtle.net/bob/hash/doobs.html */

  const uint8_t* k;
  uint32_t a, b, c;
  size_t len;

  k = (const uint8_t*) data;

  /* Set up the internal state. */
  len = length;
  a = b = 0x9e3779b9; /* The golden ratio; an arbitrary value. */
  c = initval; /* The previous hash value. */

  /*--------------------------------------- Handle most of the key. */
  while (len >= 12) {
    a += (k[0] +
          ((uint32_t) k[1] << 8) +
          ((uint32_t) k[2] << 16) +
          ((uint32_t) k[3] << 24));

    b += (k[4] +
          ((uint32_t) k[5] << 8) +
          ((uint32_t) k[6] << 16) +
          ((uint32_t) k[7] << 24));

    c += (k[8] +
          ((uint32_t) k[9] << 8) +
          ((uint32_t) k[10] << 16) +
          ((uint32_t) k[11] << 24));

    mix(a, b, c);

    k += 12;
    len -= 12;
  }

  /*------------------------------------- Handle the last 11 bytes. */
  c += length;
  switch (len) {
    case 11:
      c += ((uint32_t) k[10] << 24);
    case 10:
      c += ((uint32_t) k[9] << 16);
    case 9:
      c += ((uint32_t) k[8] << 8);

      /* The first byte of c is reserved for the length. */

    case 8:
      b += ((uint32_t) k[7] << 24);
    case 7:
      b += ((uint32_t) k[6] << 16);
    case 6:
      b += ((uint32_t) k[5] << 8);
    case 5:
      b += k[4];
    case 4:
      a += ((uint32_t) k[3] << 24);
    case 3:
      a += ((uint32_t) k[2] << 16);
    case 2:
      a += ((uint32_t) k[1] << 8);
    case 1:
      a += k[0];
    /* case 0: nothing left to add. */
  }

  mix(a, b, c);

  /*-------------------------------------------- Report the result. */
  return (c % max);
}
