// trident actor preload: reports blocked name lookups (EAI_NONAME) from any
// dynamically-linked process in the sandbox — curl, the agents' node CLIs,
// python — by appending to a local report file that the shim sweeps through
// the proxied /execute channel. Unlisted names fail at the in-sandbox
// resolver before any packet reaches the egress gateway, so this is how the
// human sees *name-based* attempts; IP-literal denials arrive via the
// gateway-log observer.
//
// Safety: the substrate server binary carries file capabilities
// (python3-ot) and therefore runs with AT_SECURE — the loader ignores
// LD_PRELOAD for it.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef int (*gai_fn)(const char *, const char *, const struct addrinfo *,
                      struct addrinfo **);
static gai_fn real_gai;

static int is_ip_literal(const char *s) {
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, s, &a4) == 1 || inet_pton(AF_INET6, s, &a6) == 1;
}

static void readfile(const char *path, char *out, size_t n) {
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fgets(out, (int)n, f)) {
        size_t l = strlen(out);
        while (l > 0 && (out[l-1] == '\n' || out[l-1] == '\r')) out[--l] = '\0';
    }
    fclose(f);
}

// report_max_inflight bounds the detached reporter threads: a process that
// fails lookups in a tight loop must not be able to spawn unbounded threads
// (or flood one file with unbounded lines).
#define REPORT_MAX_INFLIGHT 16
#define REPORT_MAX_HOST 200

static volatile int report_inflight = 0;

// sanitize_host rejects control characters, quotes and everything past a
// sane length — the report line is JSON, so an unescaped hostname would let
// a process forge requests for others or break the sweeper's parser.
static int sanitize_host(const char *in, char *out, size_t n) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 1 < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') return 0;
        out[j++] = (char)c;
    }
    if (in[0] == '\0' || (j == n - 1 && in[j] != '\0')) return 0; // too long
    out[j] = '\0';
    return j > 0;
}

static void *reporter(void *arg) {
    char *host = (char *)arg;
    // identity from the substrate system_info volume
    char actor[256];
    readfile("/mnt/ots/name", actor, sizeof actor);
    if (actor[0] == '\0') snprintf(actor, sizeof actor, "unknown");
    char line[1024];
    snprintf(line, sizeof line, "{\"host\":\"%s\",\"requestor\":\"%s\"}\n", host, actor);
    (void)!mkdir("/tmp/.ot-egress", 0755);
    int fd = open("/tmp/.ot-egress/seen.jsonl", O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0) {
        (void)!write(fd, line, strlen(line));
        close(fd);
    }
    free(host);
    (void)!__sync_sub_and_fetch(&report_inflight, 1);
    return NULL;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    if (!real_gai) real_gai = (gai_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    if (!real_gai) return EAI_SYSTEM;
    int rc = real_gai(node, service, hints, res);
    if (rc == EAI_NONAME && node && node[0] && !is_ip_literal(node)) {
        char safe[REPORT_MAX_HOST];
        if (sanitize_host(node, safe, sizeof safe)) {
            if (__sync_add_and_fetch(&report_inflight, 1) > REPORT_MAX_INFLIGHT) {
                (void)!__sync_sub_and_fetch(&report_inflight, 1); // at capacity
            } else {
                char *copy = strdup(safe);
                if (copy) {
                    pthread_t t;
                    pthread_attr_t a;
                    pthread_attr_init(&a);
                    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
                    pthread_attr_setstacksize(&a, 256 * 1024);
                    if (pthread_create(&t, &a, reporter, copy) != 0) {
                        free(copy);
                        (void)!__sync_sub_and_fetch(&report_inflight, 1);
                    }
                } else {
                    (void)!__sync_sub_and_fetch(&report_inflight, 1);
                }
            }
        }
    }
    return rc;
}
