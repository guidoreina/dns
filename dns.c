#include <stdlib.h>
#include <string.h>
#include "dns.h"
#include "macros.h"

#define MAX_POINTERS 10

static int build_cname(const char* name, size_t namelen, void* buf);
static const uint8_t* process_questions(const uint8_t* buf,
                                        const uint8_t* end,
                                        const uint8_t* pos,
                                        uint16_t n,
                                        dns_question_t* questions,
                                        size_t* nquestions);

static const uint8_t* skip_questions(const uint8_t* buf,
                                     const uint8_t* end,
                                     uint16_t n);

static const uint8_t* process_resource_records(const uint8_t* buf,
                                               const uint8_t* end,
                                               const uint8_t* pos,
                                               uint16_t nrecords,
                                               rr_t* rrs,
                                               size_t* nrrs);

static const uint8_t* skip_resource_records(const uint8_t* buf,
                                            const uint8_t* end,
                                            uint16_t nrecords);

static const uint8_t* parse_domain_name(const uint8_t* buf,
                                        const uint8_t* end,
                                        const uint8_t* pos,
                                        char* name,
                                        size_t* namelen);

static const uint8_t* skip_domain_name(const uint8_t* buf, const uint8_t* end);

int dns_build_request(uint16_t id,
                      dns_qtype_t qtype,
                      dns_qclass_t qclass,
                      const char* name,
                      size_t namelen,
                      void* buf,
                      size_t* len)
{
  uint8_t* b;
  size_t l;
  int ret;

  if (namelen <= HOSTNAME_MAX_LEN) {
    b = (uint8_t*) buf;

    /* Build header. */

    /* Set ID. */
    b[0] = (id >> 8) & 0xff;
    b[1] = id & 0xff;

    /* Set flags. */
    b[2] = 0x01; /* Recursion desired. */
    b[3] = 0x00;

    /* Set QDCOUNT. */
    b[4] = 0x00;
    b[5] = 0x01;

    /* Set ANCOUNT. */
    b[6] = 0x00;
    b[7] = 0x00;

    /* Set NSCOUNT. */
    b[8] = 0x00;
    b[9] = 0x00;

    /* Set ARCOUNT. */
    b[10] = 0x00;
    b[11] = 0x00;

    /* Build question. */

    /* Set CNAME. */
    if ((ret = build_cname(name, namelen, b + 12)) != -1) {
      l = 12 + ret;

      /* Set QTYPE. */
      b[l] = (((uint16_t) qtype) >> 8) & 0xff;
      b[l + 1] = ((uint16_t) qtype) & 0xff;

      /* Set QCLASS. */
      b[l + 2] = (((uint16_t) qclass) >> 8) & 0xff;
      b[l + 3] = ((uint16_t) qclass) & 0xff;

      *len = l + 4;

      return 0;
    }
  }

  return -1;
}

int dns_process_response(const void* buf,
                         size_t len,
                         uint16_t* id,
                         dns_question_t* questions,
                         size_t* nquestions,
                         rr_t* answers,
                         size_t* nanswers,
                         rr_t* authorities,
                         size_t* nauthorities)
{
  const uint8_t* b;
  const uint8_t* end;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t count;

  if ((len >= 12) && (len <= MAX_DNS_MESSAGE_SIZE)) {
    b = (const uint8_t*) buf;

    if (id) {
      /* Save ID. */
      *id = (b[0] << 8) | b[1];
    }

    /* If it is a response... */
    if (b[2] & 0x80) {
      /* If the message was not truncated... */
      if ((b[2] & 0x02) == 0) {
        /* If the response code is 0... */
        if ((b[3] & 0x0f) == 0) {
          /* Get the number of questions. */
          qdcount = (b[4] << 8) | b[5];

          /* Get the number of answers. */
          ancount = (b[6] << 8) | b[7];

          /* Get the number of authorities. */
          nscount = (b[8] << 8) | b[9];

          end = b + len;

          count = questions ? MIN(qdcount, *nquestions) : 0;

          /* Process questions. */
          if ((b = process_questions(buf,
                                     end,
                                     b + 12,
                                     count,
                                     questions,
                                     nquestions)) != NULL) {
            /* Skip not processed questions. */
            if ((b = skip_questions(b, end, qdcount - count)) != NULL) {
              count = answers ? MIN(ancount, *nanswers) : 0;

              /* Process answers. */
              if ((b = process_resource_records(buf,
                                                end,
                                                b,
                                                count,
                                                answers,
                                                nanswers)) != NULL) {
                /* Skip not processed answers. */
                if ((b = skip_resource_records(b,
                                               end,
                                               ancount - count)) != NULL) {
                  count = authorities ? MIN(nscount, *nauthorities) : 0;

                  /* Process authorities. */
                  if ((b = process_resource_records(buf,
                                                    end,
                                                    b,
                                                    count,
                                                    authorities,
                                                    nauthorities)) != NULL) {
                    return 0;
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return -1;
}

const char* dns_qtype_to_string(dns_qtype_t qtype)
{
  switch (qtype) {
    case DNS_QTYPE_A:
      return "A";
    case DNS_QTYPE_NS:
      return "NS";
    case DNS_QTYPE_MD:
      return "MD";
    case DNS_QTYPE_MF:
      return "MF";
    case DNS_QTYPE_CNAME:
      return "CNAME";
    case DNS_QTYPE_SOA:
      return "SOA";
    case DNS_QTYPE_MB:
      return "MB";
    case DNS_QTYPE_MG:
      return "MG";
    case DNS_QTYPE_MR:
      return "MR";
    case DNS_QTYPE_NULL:
      return "NULL";
    case DNS_QTYPE_WKS:
      return "WKS";
    case DNS_QTYPE_PTR:
      return "PTR";
    case DNS_QTYPE_HINFO:
      return "HINFO";
    case DNS_QTYPE_MINFO:
      return "MINFO";
    case DNS_QTYPE_MX:
      return "MX";
    case DNS_QTYPE_TXT:
      return "TXT";
    case DNS_QTYPE_AAAA:
      return "AAAA";
    case DNS_QTYPE_AXFR:
      return "AXFR";
    case DNS_QTYPE_MAILB:
      return "MAILB";
    case DNS_QTYPE_MAILA:
      return "MAILA";
    case DNS_QTYPE_ALL:
      return "(all)";
    default:
      return "(unknown)";
  }
}

const char* dns_qclass_to_string(dns_qclass_t qclass)
{
  switch (qclass) {
    case DNS_QCLASS_IN:
      return "IN";
    case DNS_QCLASS_CS:
      return "CS";
    case DNS_QCLASS_CH:
      return "CH";
    case DNS_QCLASS_HS:
      return "HS";
    case DNS_QCLASS_ANY:
      return "(any)";
    default:
      return "(unknown)";
  }
}

int build_cname(const char* name, size_t namelen, void* buf)
{
  const char* end;
  const char* label;
  size_t labellen;
  uint8_t* b;

  end = name + namelen;
  label = name;
  b = (uint8_t*) buf;

  while (name < end) {
    if (*name == '.') {
      if (((labellen = name - label) > 0) && (labellen <= DNS_LABEL_MAX_LEN)) {
        *b = (uint8_t) labellen;

        memcpy(b + 1, label, labellen);
        b += (1 + labellen);

        label = name + 1;
      } else {
        return -1;
      }
    }

    name++;
  }

  if (((labellen = name - label) > 0) && (labellen <= DNS_LABEL_MAX_LEN)) {
    *b = (uint8_t) labellen;

    memcpy(b + 1, label, labellen);
    b += (1 + labellen);

    /* Add null label. */
    *b++ = 0;

    return (int) (b - (uint8_t*) buf);
  }

  return -1;
}

const uint8_t* process_questions(const uint8_t* buf,
                                 const uint8_t* end,
                                 const uint8_t* pos,
                                 uint16_t n,
                                 dns_question_t* questions,
                                 size_t* nquestions)
{
  size_t count;
  uint16_t i;

  count = 0;

  /* For each question... */
  for (i = 0; i < n; i++) {
    /* Parse name. */
    if ((pos = parse_domain_name(buf,
                                 end,
                                 pos,
                                 questions->name,
                                 &questions->namelen)) != NULL) {
      if (pos + 4 <= end) {
        /* Get QTYPE. */
        questions->qtype = (pos[0] << 8) | pos[1];

        /* Get QCLASS. */
        questions->qclass = (pos[2] << 8) | pos[3];

        count++;
        questions++;

        pos += 4;
      } else {
        return NULL;
      }
    } else {
      return NULL;
    }
  }

  if (nquestions) {
    *nquestions = count;
  }

  return pos;
}

const uint8_t* skip_questions(const uint8_t* buf,
                              const uint8_t* end,
                              uint16_t n)
{
  uint16_t i;

  /* For each question... */
  for (i = 0; i < n; i++) {
    /* Skip QNAME, QTYPE and QCLASS. */
    if (((buf = skip_domain_name(buf, end)) == NULL) || ((buf += 4) > end)) {
      return NULL;
    }
  }

  return buf;
}

const uint8_t* process_resource_records(const uint8_t* buf,
                                        const uint8_t* end,
                                        const uint8_t* pos,
                                        uint16_t nrecords,
                                        rr_t* rrs,
                                        size_t* nrrs)
{
  const uint8_t* p;
  uint16_t count;
  uint16_t rdlength;
  uint16_t i;

  count = 0;

  /* For each resource record... */
  for (i = 0; i < nrecords; i++) {
    /* Parse name. */
    if ((pos = parse_domain_name(buf,
                                 end,
                                 pos,
                                 rrs->name,
                                 &rrs->namelen)) != NULL) {
      if (pos + 10 <= end) {
        /* Get RDLENGTH. */
        rdlength = (pos[8] << 8) | pos[9];

        if (pos + 10 + rdlength <= end) {
          /* Get TYPE. */
          rrs->type = (pos[0] << 8) | pos[1];

          /* Get CLASS. */
          rrs->class = (pos[2] << 8) | pos[3];

          /* Get TTL. */
          rrs->ttl = (pos[4] << 24) |
                     (pos[5] << 16) |
                     (pos[6] << 8) |
                     pos[7];

          if (rrs->class == DNS_QCLASS_IN) {
            switch (rrs->type) {
              case DNS_QTYPE_A: /* IPv4. */
                if (rdlength == 4) {
                  memcpy(&rrs->addr4, pos + 10, 4);
                  rrs->rdlength = rdlength;

                  count++;
                  rrs++;
                } else {
                  return NULL;
                }

                break;
              case DNS_QTYPE_AAAA: /* IPv6. */
                if (rdlength == 16) {
                  memcpy(&rrs->addr6, pos + 10, 16);
                  rrs->rdlength = rdlength;

                  count++;
                  rrs++;
                } else {
                  return NULL;
                }

                break;
              case DNS_QTYPE_CNAME: /* Canonical name. */
                if (parse_domain_name(buf,
                                      end,
                                      pos + 10,
                                      rrs->cname.name,
                                      &rrs->cname.namelen)) {
                  rrs->rdlength = rdlength;

                  count++;
                  rrs++;
                } else {
                  return NULL;
                }

                break;
              case DNS_QTYPE_MX: /* Mail exchange. */
                if (parse_domain_name(buf,
                                      end,
                                      pos + 12,
                                      rrs->mx.exchange,
                                      &rrs->mx.exchangelen)) {
                  rrs->mx.preference = (pos[10] << 8) | pos[11];

                  rrs->rdlength = rdlength;

                  count++;
                  rrs++;
                } else {
                  return NULL;
                }

                break;
              case DNS_QTYPE_SOA: /* Start of authority. */
                if ((p = parse_domain_name(buf,
                                           end,
                                           pos + 10,
                                           rrs->soa.nameserver,
                                           &rrs->soa.nameserverlen)) != NULL) {
                  if ((p = parse_domain_name(buf,
                                             end,
                                             p,
                                             rrs->soa.mailbox,
                                             &rrs->soa.mailboxlen)) != NULL) {
                    if (p + 20 <= end) {
                      /* Get serial number. */
                      rrs->soa.serial = (p[0] << 24) |
                                        (p[1] << 16) |
                                        (p[2] << 8) |
                                        p[3];

                      /* Get refresh interval. */
                      rrs->soa.refresh = (p[4] << 24) |
                                         (p[5] << 16) |
                                         (p[6] << 8) |
                                         p[7];

                      /* Get retry interval. */
                      rrs->soa.retry = (p[8] << 24) |
                                       (p[9] << 16) |
                                       (p[10] << 8) |
                                       p[11];

                      /* Get expire limit. */
                      rrs->soa.expire = (p[12] << 24) |
                                        (p[13] << 16) |
                                        (p[14] << 8) |
                                        p[15];

                      /* Get minimum TTL. */
                      rrs->soa.minimum_ttl = (p[16] << 24) |
                                             (p[17] << 16) |
                                             (p[18] << 8) |
                                             p[19];

                      rrs->rdlength = rdlength;

                      count++;
                      rrs++;
                    } else {
                      return NULL;
                    }
                  } else {
                    return NULL;
                  }
                } else {
                  return NULL;
                }

                break;
            }
          }

          pos += (10 + rdlength);
        } else {
          return NULL;
        }
      } else {
        return NULL;
      }
    } else {
      return NULL;
    }
  }

  if (nrrs) {
    *nrrs = count;
  }

  return pos;
}

const uint8_t* skip_resource_records(const uint8_t* buf,
                                     const uint8_t* end,
                                     uint16_t nrecords)
{
  uint16_t rdlength;
  uint16_t i;

  /* For each resource record... */
  for (i = 0; i < nrecords; i++) {
    /* Skip name. */
    if ((buf = skip_domain_name(buf, end)) != NULL) {
      if (buf + 10 <= end) {
        /* Get RDLENGTH. */
        rdlength = (buf[8] << 8) | buf[9];

        if (buf + 10 + rdlength <= end) {
          buf += (10 + rdlength);
        } else {
          return NULL;
        }
      } else {
        return NULL;
      }
    } else {
      return NULL;
    }
  }

  return buf;
}

const uint8_t* parse_domain_name(const uint8_t* buf,
                                 const uint8_t* end,
                                 const uint8_t* pos,
                                 char* name,
                                 size_t* namelen)
{
  size_t len;
  unsigned npointers;
  const uint8_t* next;
  uint8_t l;

  if (pos != end) {
    len = 0;
    npointers = 0;

    while ((l = *pos) != 0) {
      switch (l & 0xc0) {
        case 0x00: /* Not a pointer. */
          if ((pos + (1 + l) < end) && (len + (1 + l) <= HOSTNAME_MAX_LEN)) {
            if (len > 0) {
              name[len++] = '.';
            }

            memcpy(name + len, pos + 1, l);
            len += l;

            pos += (1 + l);
          } else {
            return NULL;
          }

          break;
        case 0xc0: /* Pointer. */
          if (pos + 2 <= end) {
            if (++npointers <= MAX_POINTERS) {
              /* First pointer? */
              if (npointers == 1) {
                next = pos + 2;
              }

              if ((pos = buf + (((l & 0x3f) << 8) | pos[1])) >= end) {
                return NULL;
              }
            } else {
              return NULL;
            }
          } else {
            return NULL;
          }

          break;
        default:
          return NULL;
      }
    }

    if (len > 0) {
      name[len] = 0;
      *namelen = len;

      return (npointers == 0) ? pos + 1 : next;
    }
  }

  return NULL;
}

const uint8_t* skip_domain_name(const uint8_t* buf, const uint8_t* end)
{
  uint8_t l;

  if (buf != end) {
    while ((l = *buf) != 0) {
      switch (l & 0xc0) {
        case 0x00: /* Not a pointer. */
          if ((buf += (1 + l)) >= end) {
            return NULL;
          }

          break;
        case 0xc0: /* Pointer. */
          return ((buf += 2) <= end) ? buf : NULL;
        default:
          return NULL;
      }
    }

    /* Skip null label. */
    return buf + 1;
  }

  return NULL;
}
