#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include "dns.h"
#include "dnscache.h"
#include "socket.h"
#include "ctype.h"
#include "macros.h"

#define MAX_PARAMETERS  2
#define MAX_ATTEMPTS    3
#define DNS_TIMEOUT     5000 /* [ms] */
#define PRINT_QUESTIONS 1
#define MAX_QUESTIONS   8
#define MAX_ANSWERS     8
#define MAX_AUTHORITIES 8

#define NUMBER_BUCKETS  127

typedef enum {
  CMD_UNKNOWN,
  CMD_HELP,
  CMD_RESOLVE,
  CMD_QUIT
} command_t;

typedef enum {
  EMPTY_LINE,
  UNKNOWN_COMMAND,
  TOO_MANY_PARAMETERS,
  PARSE_SUCCEEDED
} parse_result_t;

static void usage(const char* program);
static void help(void);
static void cmdhelp(command_t cmd);

static parse_result_t parse_command_line(char* line,
                                         command_t* cmd,
                                         const char** parameters,
                                         unsigned* nparameters);

static command_t find_command(const char* cmd, size_t len);
static int yes_or_no(const char* msg);

static void process_help(const char** parameters, unsigned nparameters);
static void process_resolve(const char** parameters,
                            unsigned nparameters,
                            int fd,
                            const struct sockaddr* addr,
                            socklen_t addrlen,
                            dnscaches_t* caches);

static int process_quit(const char** parameters, unsigned nparameters);

static void print_response(uint16_t id,
                           const dns_question_t* questions,
                           size_t nquestions,
                           const rr_t* answers,
                           size_t nanswers,
                           const rr_t* authorities,
                           size_t nauthorities);

static void print_rr(const rr_t* rr);

static void add_to_dns_cache(dnscaches_t* caches, const rr_t* rrs, size_t nrrs);

int main(int argc, const char** argv)
{
  struct sockaddr_storage addr;
  socklen_t addrlen;
  int fd;
  dnscaches_t caches;
  char line[512];
  command_t cmd;
  const char* parameters[MAX_PARAMETERS];
  unsigned nparameters;

  /* Check usage. */
  if (argc != 2) {
    usage(argv[0]);
    return -1;
  }

  if (build_socket_address(argv[1], &addr, &addrlen) < 0) {
    fprintf(stderr, "Invalid socket address '%s'.\n", argv[1]);
    return -1;
  }

  /* Create socket. */
  if ((fd = socket_create(addr.ss_family, SOCK_DGRAM)) < 0) {
    fprintf(stderr, "Error creating socket.\n");
    return -1;
  }

  /* Create DNS caches. */
  if (dnscaches_create(&caches, NUMBER_BUCKETS) < 0) {
    fprintf(stderr, "Error creating DNS caches.\n");

    close(fd);
    return -1;
  }

  do {
    printf("dns> ");

    /* Read command. */
    fgets(line, sizeof(line), stdin);

    switch (parse_command_line(line, &cmd, parameters, &nparameters)) {
      case EMPTY_LINE:
        break;
      case UNKNOWN_COMMAND:
      case TOO_MANY_PARAMETERS:
        help();
        break;
      case PARSE_SUCCEEDED:
        switch (cmd) {
          case CMD_HELP:
            process_help(parameters, nparameters);
            break;
          case CMD_RESOLVE:
            process_resolve(parameters,
                            nparameters,
                            fd,
                            (const struct sockaddr*) &addr,
                            addrlen,
                            &caches);

            break;
          case CMD_QUIT:
            if (process_quit(parameters, nparameters)) {
              dnscaches_destroy(&caches);
              close(fd);

              return 0;
            }

            cmdhelp(CMD_QUIT);

            break;
          case CMD_UNKNOWN:
            break;
        }

        break;
    }
  } while (1);
}

void usage(const char* program)
{
  printf("Usage: %s <DNS-server-address>\n", program);
}

void help(void)
{
  command_t cmd;

  printf("Commands:\n");

  for (cmd = CMD_HELP; cmd <= CMD_QUIT; cmd++) {
    cmdhelp(cmd);
  }

  printf("\n");
}

void cmdhelp(command_t cmd)
{
  switch (cmd) {
    case CMD_RESOLVE:
      printf("  resolve <QCLASS> <name>: resolves <name>\n");
      printf("          <QCLASS> ::= \"A\" | \"CNAME\" | \"MX\" | \"AAAA\" | "
             "\"SOA\"\n");

      printf("\n");

      break;
    case CMD_HELP:
      printf("  help: shows this help.\n");
      printf("\n");

      break;
    case CMD_QUIT:
      printf("  quit: quits the program.\n");
      printf("\n");

      break;
    case CMD_UNKNOWN:
      help();
      break;
  }
}

parse_result_t parse_command_line(char* line,
                                  command_t* cmd,
                                  const char** parameters,
                                  unsigned* nparameters)
{
  const char* cmdstr;
  unsigned count;

  /* Skip initial spaces (if any). */
  while ((*line == ' ') || (*line == '\t')) {
    line++;
  }

  /* If the line is empty... */
  if ((!*line) || (*line == '\n')) {
    return EMPTY_LINE;
  }

  /* Save beginning of the command. */
  cmdstr = line;

  /* Skip command. */
  while (*line > ' ') {
    line++;
  }

  if ((*cmd = find_command(cmdstr, line - cmdstr)) == CMD_UNKNOWN) {
    return UNKNOWN_COMMAND;
  }

  count = 0;

  do {
    /* Skip spaces (if any). */
    while ((*line == ' ') || (*line == '\t')) {
      line++;
    }

    /* End of line? */
    if ((!*line) || (*line == '\n')) {
      break;
    }

    /* Too many parameters? */
    if (++count > MAX_PARAMETERS) {
      return TOO_MANY_PARAMETERS;
    }

    /* Save beginning of the parameter. */
    parameters[count - 1] = line;

    /* Skip parameter. */
    while (*line > ' ') {
      line++;
    }

    /* NUL terminate parameter. */
    *line++ = 0;
  } while (1);

  *nparameters = count;

  return PARSE_SUCCEEDED;
}

command_t find_command(const char* cmd, size_t len)
{
  switch (len) {
    case 7:
      if (strncasecmp(cmd, "resolve", 7) == 0) {
        return CMD_RESOLVE;
      }

      break;
    case 4:
      if (strncasecmp(cmd, "help", 4) == 0) {
        return CMD_HELP;
      } else if (strncasecmp(cmd, "quit", 4) == 0) {
        return CMD_QUIT;
      }

      break;
  }

  return CMD_UNKNOWN;
}

int yes_or_no(const char* msg)
{
  char line[512];
  const char* ptr;
  int ret;

  do {
    printf("%s (Y/N)? ", msg);
    fgets(line, sizeof(line), stdin);

    ptr = line;

    /* Skip spaces (if any). */
    while ((*ptr == ' ') || (*ptr == '\t')) {
      ptr++;
    }

    switch (*ptr) {
      case 'Y':
      case 'y':
        ret = 1;
        break;
      case 'N':
      case 'n':
        ret = 0;
        break;
      default:
        continue;
    }

    ptr++;

    while ((*ptr) && (*ptr <= ' ')) {
      ptr++;
    }

    if (!*ptr) {
      return ret;
    }
  } while (1);
}

void process_help(const char** parameters, unsigned nparameters)
{
  if (nparameters != 1) {
    help();
  } else {
    cmdhelp(find_command(parameters[0], strlen(parameters[0])));
  }
}

void process_resolve(const char** parameters,
                     unsigned nparameters,
                     int fd,
                     const struct sockaddr* addr,
                     socklen_t addrlen,
                     dnscaches_t* caches)
{
  dns_qtype_t qtype;
  char host[HOSTNAME_MAX_LEN + 1];
  size_t hostlen;
  size_t j;
  uint8_t request[MAX_DNS_MESSAGE_SIZE];
  uint8_t response[MAX_DNS_MESSAGE_SIZE];
  size_t len;
  ssize_t l;
  unsigned i;

  struct in_addr addr4;
  struct in6_addr addr6;
  char buf[128];

#if PRINT_QUESTIONS
  dns_question_t questions[MAX_QUESTIONS];
  size_t nquestions;
#endif /* PRINT_QUESTIONS */

  uint16_t id;
  rr_t answers[MAX_ANSWERS];
  size_t nanswers;
  rr_t authorities[MAX_AUTHORITIES];
  size_t nauthorities;

  if (nparameters != 2) {
    cmdhelp(CMD_RESOLVE);
    return;
  }

  if ((hostlen = strlen(parameters[1])) > HOSTNAME_MAX_LEN) {
    printf("Hostname too long (%zu characters, maximum: %u).\n",
           hostlen,
           HOSTNAME_MAX_LEN);

    return;
  }

  for (j = 0; j < hostlen; j++) {
    host[j] = to_lower(parameters[1][j]);
  }

  host[j] = 0;

  if (strcasecmp(parameters[0], "A") == 0) {
    if (dnscaches_get_ipv4(caches,
                           host,
                           hostlen,
                           time(NULL),
                           &addr4) == 0) {
      if (inet_ntop(AF_INET, &addr4, buf, sizeof(buf))) {
        printf("(From cache) IPv4: %s\n", buf);
      }

      return;
    }

    qtype = DNS_QTYPE_A;
  } else if (strcasecmp(parameters[0], "CNAME") == 0) {
    qtype = DNS_QTYPE_CNAME;
  } else if (strcasecmp(parameters[0], "MX") == 0) {
    qtype = DNS_QTYPE_MX;
  } else if (strcasecmp(parameters[0], "AAAA") == 0) {
    if (dnscaches_get_ipv6(caches,
                           host,
                           hostlen,
                           time(NULL),
                           &addr6) == 0) {
      if (inet_ntop(AF_INET6, &addr6, buf, sizeof(buf))) {
        printf("(From cache) IPv6: %s\n", buf);
      }

      return;
    }

    qtype = DNS_QTYPE_AAAA;
  } else if (strcasecmp(parameters[0], "SOA") == 0) {
    qtype = DNS_QTYPE_SOA;
  } else {
    cmdhelp(CMD_RESOLVE);
    return;
  }

  /* Build DNS request. */
  if (dns_build_request(random() % 65536,
                        qtype,
                        DNS_QCLASS_IN,
                        host,
                        hostlen,
                        request,
                        &len) != 0) {
    printf("Error building DNS request.\n");
    return;
  }

  for (i = 0; i < MAX_ATTEMPTS; i++) {
    /* Send DNS request. */
    if (socket_timed_sendto(fd,
                            request,
                            len,
                            addr,
                            addrlen,
                            DNS_TIMEOUT) == (ssize_t) len) {
      /* Receive response. */
      if ((l = socket_timed_recvfrom(fd,
                                     response,
                                     sizeof(response),
                                     NULL,
                                     NULL,
                                     DNS_TIMEOUT)) > 0) {
        /* Process response. */
#if PRINT_QUESTIONS
        nquestions = ARRAY_SIZE(questions);
#endif

        nanswers = ARRAY_SIZE(answers);
        nauthorities = ARRAY_SIZE(authorities);

        if (dns_process_response(response,
                                 l,
                                 &id,
#if PRINT_QUESTIONS
                                 questions,
                                 &nquestions,
#else
                                 NULL,
                                 NULL,
#endif
                                 answers,
                                 &nanswers,
                                 authorities,
                                 &nauthorities) == 0) {
          print_response(id,
                         questions,
                         nquestions,
                         answers,
                         nanswers,
                         authorities,
                         nauthorities);

          if (yes_or_no("Add to DNS cache")) {
            add_to_dns_cache(caches, answers, nanswers);
          }
        } else {
          printf("Error processing response.\n");
        }

        return;
      }
    }
  }

  printf("Error resolving DNS request.\n");
}

int process_quit(const char** parameters, unsigned nparameters)
{
  return (nparameters == 0);
}

void print_response(uint16_t id,
                    const dns_question_t* questions,
                    size_t nquestions,
                    const rr_t* answers,
                    size_t nanswers,
                    const rr_t* authorities,
                    size_t nauthorities)
{
  size_t i;

  printf("Id: 0x%x\n", id);

#if PRINT_QUESTIONS
  if (nquestions > 0) {
    printf("Questions:\n");

    /* Print questions. */
    for (i = 0; i < nquestions; i++) {
      printf("  Question:\n");

      printf("    Name: '%s'\n", questions[i].name);
      printf("    Type: %s (%u)\n",
             dns_qtype_to_string(questions[i].qtype),
             questions[i].qtype);

      printf("    Class: %s (0x%04x)\n",
             dns_qclass_to_string(questions[i].qclass),
             questions[i].qclass);

      printf("\n");
    }
  }
#endif /* PRINT_QUESTIONS */

  if (nanswers > 0) {
    printf("Answers:\n");

    /* Print answers. */
    for (i = 0; i < nanswers; i++) {
      printf("  Resource record:\n");

      print_rr(answers + i);

      printf("\n");
    }
  }

  if (nauthorities > 0) {
    printf("Authorities:\n");

    /* Print authorities. */
    for (i = 0; i < nauthorities; i++) {
      printf("  Resource record:\n");

      print_rr(authorities + i);

      printf("\n");
    }
  }
}

void print_rr(const rr_t* rr)
{
  char buf[128];

  printf("    Name: '%s'\n", rr->name);
  printf("    Type: %s (%u)\n", dns_qtype_to_string(rr->type), rr->type);
  printf("    Class: %s (0x%04x)\n",
         dns_qclass_to_string(rr->class),
         rr->class);

  printf("    Time to live: %u\n", rr->ttl);
  printf("    Data length: %zu\n", rr->rdlength);

  switch (rr->type) {
    case DNS_QTYPE_A:
      if (inet_ntop(AF_INET, &rr->addr4, buf, sizeof(buf))) {
        printf("    IPv4: %s\n", buf);
      }

      break;
    case DNS_QTYPE_AAAA:
      if (inet_ntop(AF_INET6, &rr->addr6, buf, sizeof(buf))) {
        printf("    IPv6: %s\n", buf);
      }

      break;
    case DNS_QTYPE_CNAME:
      printf("    CNAME: '%s'\n", rr->cname.name);
      break;
    case DNS_QTYPE_MX:
      printf("    Preference: %u\n", rr->mx.preference);
      printf("    Exchange: '%s'\n", rr->mx.exchange);

      break;
    case DNS_QTYPE_SOA:
      printf("    Primary name server: '%s'\n", rr->soa.nameserver);
      printf("    Responsible authority's mailbox: '%s'\n", rr->soa.mailbox);
      printf("    Serial number: %u\n", rr->soa.serial);
      printf("    Refresh interval: %u\n", rr->soa.refresh);
      printf("    Retry interval: %u\n", rr->soa.retry);
      printf("    Expire limit: %u\n", rr->soa.expire);
      printf("    Minimum TTL: %u\n", rr->soa.minimum_ttl);

      break;
  }
}

void add_to_dns_cache(dnscaches_t* caches, const rr_t* rrs, size_t nrrs)
{
  const char* name;
  size_t namelen;
  const char* cname;
  size_t cnamelen;
  time_t now;
  char buf[128];
  size_t i;

  name = NULL;
  cname = NULL;
  cnamelen = 0;

  now = time(NULL);

  for (i = 0; i < nrrs; i++) {
    if (!name) {
      name = rrs[i].name;
      namelen = rrs[i].namelen;
    }

    switch (rrs[i].type) {
      case DNS_QTYPE_A:
        if (cname) {
          if ((cnamelen != rrs[i].namelen) ||
              (memcmp(cname, rrs[i].name, cnamelen) != 0)) {
            name = rrs[i].name;
            namelen = rrs[i].namelen;
          }
        }

        if (dnscaches_add_ipv4(caches,
                               name,
                               namelen,
                               &rrs[i].addr4,
                               now + rrs[i].ttl,
                               now) == 0) {
          if (inet_ntop(AF_INET, &rrs[i].addr4, buf, sizeof(buf))) {
            printf("Added '%s' -> %s to DNS cache.\n", name, buf);
          }
        } else {
          printf("Error adding '%s' to DNS cache.\n", name);
        }

        return;
      case DNS_QTYPE_AAAA:
        if (cname) {
          if ((cnamelen != rrs[i].namelen) ||
              (memcmp(cname, rrs[i].name, cnamelen) != 0)) {
            name = rrs[i].name;
            namelen = rrs[i].namelen;
          }
        }

        if (dnscaches_add_ipv6(caches,
                               name,
                               namelen,
                               &rrs[i].addr6,
                               now + rrs[i].ttl,
                               now) == 0) {
          if (inet_ntop(AF_INET6, &rrs[i].addr6, buf, sizeof(buf))) {
            printf("Added '%s' -> %s to DNS cache.\n", name, buf);
          }
        } else {
          printf("Error adding '%s' to DNS cache.\n", name);
        }

        return;
      case DNS_QTYPE_CNAME:
        if ((!cname) ||
            ((cnamelen == rrs[i].namelen) &&
             (memcmp(cname, rrs[i].name, cnamelen) == 0))) {
          cname = rrs[i].cname.name;
          cnamelen = rrs[i].cname.namelen;
        }

        break;
    }
  }
}
