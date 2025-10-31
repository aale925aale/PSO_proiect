#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>      
#include <sys/socket.h>     
#include <netdb.h>          
#include <arpa/inet.h>      
#include <errno.h> 

#define BUFFER_SIZE 4096

int connect_to_host(const char *host, int port) {
    struct addrinfo hints, *res, *p;
    char port_str[6];
    int sock = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock;
}

void send_request(int sock, const char *method, const char *host, const char *path, const char *body) {
    char request[2048];
    if (strcasecmp(method, "POST") == 0 && body != NULL) {
        int len = strlen(body);
        snprintf(request, sizeof(request),
                 "POST %s HTTP/1.0\r\n"
                 "Host: %s\r\n"
                 "User-Agent: mini-client/1.0\r\n"
                 "Content-Type: application/x-www-form-urlencoded\r\n"
                 "Content-Length: %d\r\n"
                 "\r\n"
                 "%s",
                 path, host, len, body);
    } else {
        snprintf(request, sizeof(request),
                 "%s %s HTTP/1.0\r\n"
                 "Host: %s\r\n"
                 "User-Agent: mini-client/1.0\r\n"
                 "Accept: */*\r\n"
                 "\r\n",
                 method, path, host);
    }

    ssize_t sent = send(sock, request, strlen(request), 0);
    if (sent < 0) perror("send");
}

void read_and_parse_response(int sock) {
    char buf[4096];
    int total = 0;
    char *response = NULL;
    ssize_t r;

    // Citește până la EOF sau până găsim \r\n\r\n
    while ((r = recv(sock, buf, sizeof(buf), 0)) > 0) {
        response = realloc(response, total + r + 1);
        memcpy(response + total, buf, r);
        total += r;
        response[total] = '\0';
        if (strstr(response, "\r\n\r\n")) break; // avem headerele
    }
    if (r < 0) perror("recv");

    if (!response) return;

    // Gasim separatorul
    char *sep = strstr(response, "\r\n\r\n");
    int header_len = sep ? (sep - response) : total;
    char *headers = strndup(response, header_len);
    char *body = sep ? strdup(sep + 4) : strdup("");

    // Prima linie
    char *line_end = strstr(headers, "\r\n");
    if (line_end) {
        char *status_line = strndup(headers, line_end - headers);
        printf("Status-line: %s\n", status_line);
        free(status_line);
    }

    // Afisam headere
    printf("Headers:\n%s\n", headers);
    printf("Body (partial, rest may arrive after):\n%s\n", body);

    free(headers);
    free(body);

    // Daca exista restul (server poate trimite in continuare), citim restul
    while ((r = recv(sock, buf, sizeof(buf), 0)) > 0) {
        fwrite(buf, 1, r, stdout);
    }
    free(response);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s GET  <host> <path> <port>\n", argv[0]);
        fprintf(stderr, "  %s POST <host> <path> <port> \"body_data\"\n", argv[0]);
        return 1;
    }

    const char *method = argv[1];
    const char *host   = argv[2];
    const char *path   = argv[3];
    int port           = atoi(argv[4]);
    const char *body   = (argc >= 6) ? argv[5] : NULL;

    int sock = connect_to_host(host, port);
    if (sock < 0) {
        fprintf(stderr, "Failed to connect to %s:%d\n", host, port);
        return 2;
    }

    send_request(sock, method, host, path, body);
    read_and_parse_response(sock);
    close(sock);
    return 0;
}
