#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <netinet/in.h>

#define HOSTNAME_MAX_LEN     255
#define DNS_LABEL_MAX_LEN    63
#define MAX_DNS_MESSAGE_SIZE 512

typedef enum {
  DNS_QTYPE_A     = 1,
  DNS_QTYPE_NS    = 2,
  DNS_QTYPE_MD    = 3,
  DNS_QTYPE_MF    = 4,
  DNS_QTYPE_CNAME = 5,
  DNS_QTYPE_SOA   = 6,
  DNS_QTYPE_MB    = 7,
  DNS_QTYPE_MG    = 8,
  DNS_QTYPE_MR    = 9,
  DNS_QTYPE_NULL  = 10,
  DNS_QTYPE_WKS   = 11,
  DNS_QTYPE_PTR   = 12,
  DNS_QTYPE_HINFO = 13,
  DNS_QTYPE_MINFO = 14,
  DNS_QTYPE_MX    = 15,
  DNS_QTYPE_TXT   = 16,
  DNS_QTYPE_AAAA  = 28,
  DNS_QTYPE_AXFR  = 252,
  DNS_QTYPE_MAILB = 253,
  DNS_QTYPE_MAILA = 254,
  DNS_QTYPE_ALL   = 255
} dns_qtype_t;

typedef enum {
  DNS_QCLASS_IN  = 1,
  DNS_QCLASS_CS  = 2,
  DNS_QCLASS_CH  = 3,
  DNS_QCLASS_HS  = 4,
  DNS_QCLASS_ANY = 255
} dns_qclass_t;

typedef struct {
  char name[HOSTNAME_MAX_LEN + 1];
  size_t namelen;

  uint16_t qtype;
  uint16_t qclass;
} dns_question_t;

typedef struct {
  char name[HOSTNAME_MAX_LEN + 1];
  size_t namelen;
} cname_rdata_t;

typedef struct {
  char exchange[HOSTNAME_MAX_LEN + 1];
  size_t exchangelen;

  uint16_t preference;
} mx_rdata_t;

typedef struct {
  char nameserver[HOSTNAME_MAX_LEN + 1];
  size_t nameserverlen;

  char mailbox[HOSTNAME_MAX_LEN + 1];
  size_t mailboxlen;

  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minimum_ttl;
} soa_rdata_t;

typedef struct {
  char name[HOSTNAME_MAX_LEN + 1];
  size_t namelen;

  uint16_t type;
  uint16_t class;

  uint32_t ttl;

  union {
    struct in_addr addr4;
    struct in6_addr addr6;
    cname_rdata_t cname;
    mx_rdata_t mx;
    soa_rdata_t soa;
  };

  size_t rdlength;
} rr_t;

int dns_build_request(uint16_t id,
                      dns_qtype_t qtype,
                      dns_qclass_t qclass,
                      const char* name,
                      size_t namelen,
                      void* buf,
                      size_t* len);

int dns_process_response(const void* buf,
                         size_t len,
                         uint16_t* id,
                         dns_question_t* questions,
                         size_t* nquestions,
                         rr_t* answers,
                         size_t* nanswers,
                         rr_t* authorities,
                         size_t* nauthorities);

const char* dns_qtype_to_string(dns_qtype_t qtype);
const char* dns_qclass_to_string(dns_qclass_t qclass);

#endif /* DNS_H */
