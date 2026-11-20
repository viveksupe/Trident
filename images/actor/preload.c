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
    return NULL;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    if (!real_gai) real_gai = (gai_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    if (!real_gai) return EAI_SYSTEM;
    int rc = real_gai(node, service, hints, res);
    if (rc == EAI_NONAME && node && node[0] && !is_ip_literal(node)) {
        char *copy = strdup(node);
        if (copy) {
            pthread_t t;
            pthread_attr_t a;
            pthread_attr_init(&a);
            pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
            pthread_attr_setstacksize(&a, 256 * 1024);
            if (pthread_create(&t, &a, reporter, copy) != 0) free(copy);
            pthread_attr_destroy(&a);
        }
    }
    return rc;
}
