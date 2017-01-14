#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <string.h>

uint32_t hash4(const void* data, uint32_t max);
uint32_t hash16(const void* data, uint32_t initval, uint32_t max);
uint32_t hash(const void* data, size_t length, uint32_t initval, uint32_t max);

static inline uint32_t hash_string(const char* s,
                                   uint32_t initval,
                                   uint32_t max)
{
  return hash(s, strlen(s), initval, max);
}

#endif /* HASH_H */
