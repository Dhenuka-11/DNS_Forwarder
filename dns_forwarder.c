#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define BUF_SIZE 512
#define PORT 53
#define BLOCK_FILE "denylist.txt"
#define LOG_FILE "queries.log"
#define UPSTREAM_DNS "8.8.8.8"

int blocked(char *domain) {
    FILE *f = fopen(BLOCK_FILE, "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strcasecmp(domain, line) == 0) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

void log_query(char *domain, char *type, int allow) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    fprintf(f, "%s %s %s\n", domain, type, allow ? "ALLOW" : "DENY");
    fclose(f);
}

int send_upstream(unsigned char *req, int len, unsigned char *resp) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, UPSTREAM_DNS, &addr.sin_addr);

    struct timeval t = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));

    sendto(sock, req, len, 0, (struct sockaddr *)&addr, sizeof(addr));

    socklen_t addr_len = sizeof(addr);
    int n = recvfrom(sock, resp, BUF_SIZE, 0, (struct sockaddr *)&addr, &addr_len);
    close(sock);
    return n;
}

void get_query_info(unsigned char *buf, int len, char *domain, char *type) {
    int pos = 12, i = 0;
    while (pos < len && buf[pos] != 0) {
        int l = buf[pos++];
        for (int j = 0; j < l; j++)
            domain[i++] = buf[pos++];
        domain[i++] = '.';
    }
    if (i > 0) domain[i-1] = 0;

    pos++;
    if (pos + 1 < len) {
        int t = (buf[pos] << 8) | buf[pos+1];
        switch (t) {
            case 1: strcpy(type, "A"); break;
            case 2: strcpy(type, "NS"); break;
            case 5: strcpy(type, "CNAME"); break;
            case 15: strcpy(type, "MX"); break;
            case 28: strcpy(type, "AAAA"); break;
            default: sprintf(type, "TYPE%d", t); break;
        }
    } else {
        strcpy(type, "UNKNOWN");
    }
}

int main() {
    int sock;
    struct sockaddr_in server, client;
    socklen_t client_len = sizeof(client);
    unsigned char buf[BUF_SIZE], resp[BUF_SIZE];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    if (bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind"); return 1;
    }

    printf("DNS server running on port %d...\n", PORT);

    while (1) {
        int n = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr *)&client, &client_len);
        if (n < 0) { perror("recvfrom"); continue; }

        char domain[256] = {0}, type[16] = {0};
        get_query_info(buf, n, domain, type);

        if (blocked(domain)) {
            unsigned char b[BUF_SIZE];
            memcpy(b, buf, n);
            b[2] = (b[2] & 0x79) | 0x80;
            b[3] = (b[3] & 0xF0) | 0x03;
            memset(b + 6, 0, 6);
            sendto(sock, b, n, 0, (struct sockaddr *)&client, client_len);
            log_query(domain, type, 0);
            printf("Blocked: %s\n", domain);
        } else {
            int rlen = send_upstream(buf, n, resp);
            if (rlen > 0) {
                sendto(sock, resp, rlen, 0, (struct sockaddr *)&client, client_len);
                log_query(domain, type, 1);
            } else {
                unsigned char f[BUF_SIZE];
                memcpy(f, buf, n);
                f[2] = (f[2] & 0x79) | 0x80;
                f[3] = (f[3] & 0xF0) | 0x02;
                memset(f + 6, 0, 6);
                sendto(sock, f, n, 0, (struct sockaddr *)&client, client_len);
                log_query(domain, type, 0);
                printf("Upstream fail: %s\n", domain);
            }
        }
    }

    close(sock);
    return 0;
}
