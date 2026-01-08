#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <strings.h>

#include "myqueue.h"

#define PORT 8080
#define BUFFER_SIZE 1024
#define THREAD_POOL_SIZE 20
#define MAX_REQ_PER_CONN 50

#define MAX_HEADER_SIZE (16 * 1024)
#define MAX_BODY_SIZE   (256 * 1024)
#define MAX_REQUEST_SIZE (MAX_HEADER_SIZE + MAX_BODY_SIZE)

#define SESSION_TTL_SECONDS (60 * 60) // 1 ora

pthread_t thread_pool[THREAD_POOL_SIZE];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

// Adaug un mutex pentru log-urile de pe server
FILE* log_file;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char method[8];
    char path[1024];
    char protocol[32];

    const char* headers;     // pointer in buffer, inceputul headerelor
    const char* body;        // pointer in buffer, inceputul body-ului
    size_t body_length;      // lungimea body-ului (pentru POST)
} http_request_t;

// DENISA --------------------------------------

/* ======= STRUCTURA pentru sesiuni (in-memory) ======= */
typedef struct session_s {
    char id[65];               // SID hex (64) + null
    char username[128];
    time_t expiry;
    struct session_s *next;
} session_t;

static session_t *sessions_head = NULL;
static pthread_mutex_t sessions_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ======= STRUCTURA utilizatori in memorie (incarcare din users.txt) ======= */
typedef struct user_s {
    char username[128];
    char password[128]; // plain text pentru exemplu (imbunatatire: stocare hash)
    struct user_s *next;
} user_t;

static user_t *users_head = NULL;
static pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;

// DENISA --------------------------------------


int parse_http_request(char* buffer, int length, http_request_t* req) {
    // Ne asiguram ca avem terminator de sir
    buffer[length] = '\0';

    // Prima linie: metoda, cale, protocol
    if (sscanf(buffer, "%7s %1023s %31s",
               req->method, req->path, req->protocol) != 3) {
        return -1; // request invalid
    }

    // Cautam inceputul headerelor (dupa prima linie)
    char* p = strstr(buffer, "\r\n");
    if (!p) {
        req->headers = NULL;
        req->body = NULL;
        req->body_length = 0;
        return 0;
    }
    p += 2; // sarim peste "\r\n"
    req->headers = p;

    // Cautam separatorul intre headere si body: "\r\n\r\n"
    char* body_start = strstr(buffer, "\r\n\r\n");
    if (body_start) {
        body_start += 4; // sarim peste "\r\n\r\n"
        req->body = body_start;
        req->body_length = (buffer + length) - body_start;
        if (req->body_length < 0) req->body_length = 0;
    } else {
        req->body = NULL;
        req->body_length = 0;
    }

    return 0;
}

// ======= functii pentru log-uri server =========
static void get_timestamp(char *out, size_t out_sz)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm tm_info;
    localtime_r(&tv.tv_sec, &tm_info);

    // format: YYYY-MM-DD HH:MM:SS.mmm
    snprintf(out, out_sz,
             "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm_info.tm_year + 1900,
             tm_info.tm_mon + 1,
             tm_info.tm_mday,
             tm_info.tm_hour,
             tm_info.tm_min,
             tm_info.tm_sec,
             tv.tv_usec / 1000);
}

static void log_request_line(int client_fd, const http_request_t *req, int status_code, long bytes_sent)
{
    if (!log_file) return;

    // afla IP/port client (peer)
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    char ip[INET_ADDRSTRLEN] = "unknown";
    int port = 0;

    if (getpeername(client_fd, (struct sockaddr *)&peer, &peer_len) == 0) {
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        port = ntohs(peer.sin_port);
    }

    char ts[64];
    get_timestamp(ts, sizeof(ts));

    pthread_mutex_lock(&log_mutex);
    fprintf(log_file,
            "%s | tid=%lu | %s:%d | %s %s %s | status=%d | bytes=%ld\n",
            ts,
            (unsigned long)pthread_self(),
            ip, port,
            req->method, req->path, req->protocol,
            status_code,
            bytes_sent);
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
}

static void log_simple(int client_fd, const char *msg)
{
    if (!log_file) return;

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    char ip[INET_ADDRSTRLEN] = "unknown";
    int port = 0;

    if (getpeername(client_fd, (struct sockaddr *)&peer, &peer_len) == 0) {
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
        port = ntohs(peer.sin_port);
    }

    char ts[64];
    get_timestamp(ts, sizeof(ts));

    pthread_mutex_lock(&log_mutex);
    fprintf(log_file,
            "%s | tid=%lu | %s:%d | %s\n",
            ts,
            (unsigned long)pthread_self(),
            ip, port,
            msg);
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
}


// ======== functii pentru coduri de eroare ==========
void send_501(int client_fd, const char* method) {
    // 501 = Metoda HTTP nu e implementata
    char body[512];
    snprintf(body, sizeof(body),
        "<html>"
        "<head><title>501 Not Implemented</title></head>"
        "<body style='font-family: Arial;'>"
        "<h1>501 - Metoda %s nu este implementata</h1>"
        "<p>Serverul HTTP nu suporta aceasta metoda.</p>"
        "</body>"
        "</html>",
        method
    );

    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 501 Not Implemented\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        strlen(body)
    );

    // trimitem header + body
    send(client_fd, header, strlen(header), 0);
    send(client_fd, body, strlen(body), 0);

    char msg[256];
    snprintf(msg, sizeof(msg), "RESP 501 Not Implemented method=%s", method);
    log_simple(client_fd, msg);

}

void send_404(int client_fd, const char* path) {
    // 404 = pagina cautata de client nu exista pe server
    char body[512];
    snprintf(body, sizeof(body),
        "<html>"
        "<head><title>404 Not Found</title></head>"
        "<body style='font-family: Arial;'>"
        "<h1>404 - Resursa %s nu a fost gasita</h1>"
        "<p>Serverul HTTP nu a putut gasi fisierul cerut.</p>"
        "</body>"
        "</html>",
        path
    );

    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        strlen(body)
    );

    send(client_fd, header, strlen(header), 0);
    send(client_fd, body, strlen(body), 0);

    char msg[1400];
    snprintf(msg, sizeof(msg), "RESP 404 Not Found path=%s", path);
    log_simple(client_fd, msg);
}

void send_400(int client_fd) {
    // 400 = format request invalid
    const char* body =
        "<html>"
        "<head><title>400 Bad Request</title></head>"
        "<body style='font-family: Arial;'>"
        "<h1>400 - Cerere invalida</h1>"
        "<p>Serverul nu poate procesa acest request deoarece formatul este invalid.</p>"
        "</body>"
        "</html>";

    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 400 Bad Request\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        strlen(body)
    );

    send(client_fd, header, strlen(header), 0);
    send(client_fd, body, strlen(body), 0);

    log_simple(client_fd, "RESP 400 Bad Request");

}

void send_200(int client_fd, const char* content_type, const char* body, int keep_alive) {
    // 200 = request procesat cu succes
    char header[256];

    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n",
        content_type,
        strlen(body),
        keep_alive ? "keep-alive" : "close",
        keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
    );
    // trimite header-ul
    send(client_fd, header, strlen(header), 0);

    // trimite body
    send(client_fd, body, strlen(body), 0);

    log_simple(client_fd, keep_alive ? "RESP 200 OK (text, keep-alive)" : "RESP 200 OK (text, close)");
}

void send_200_raw(int client_fd, const char* content_type, const char* data, size_t length, int keep_alive)
{
    // 200 raw = pt fisiere binare (imagini, css, js...)
    char header[256];

    snprintf(header, sizeof(header),
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %zu\r\n"
    "Connection: %s\r\n"
    "%s"
    "\r\n",
    content_type,
    length,
    keep_alive ? "keep-alive" : "close",
    keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
);

    send(client_fd, header, strlen(header), 0);
    send(client_fd, data, length, 0);

    char msg[256];
    snprintf(msg, sizeof(msg), "RESP 200 OK (raw) len=%zu type=%s %s",length, content_type, keep_alive ? "KA" : "CLOSE");
    log_simple(client_fd, msg);

}

// DENISA begin ---------------------------

/* ======== trimite doar header-ele (fara body) - folosit de HEAD ======= */
void send_200_headers(int client_fd, const char* content_type, size_t length, int keep_alive)
{
    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n",
        content_type,
        length,
        keep_alive ? "keep-alive" : "close",
        keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
    );
    send(client_fd, header, strlen(header), 0);

    char msg[256];
    snprintf(msg, sizeof(msg), "RESP 200 OK (headers) len=%zu type=%s %s", length, content_type, keep_alive ? "KA" : "CLOSE");
    log_simple(client_fd, msg);
}

/* ======== trimite Allow pentru OPTIONS (folosesc 204 No Content) ======= */
void send_204_allow(int client_fd, int keep_alive)
{
    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 204 No Content\r\n"
        "Allow: GET, POST, HEAD, OPTIONS\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n",
        keep_alive ? "keep-alive" : "close",
        keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
    );
    send(client_fd, header, strlen(header), 0);

    log_simple(client_fd, keep_alive ? "RESP 204 No Content (Allow) KA" : "RESP 204 No Content (Allow) CLOSE");
}

/* ======== redirect cu cookie (folosit dupa login) ======= */
void send_302_set_cookie_and_location(int client_fd, const char* cookie, const char* location, int keep_alive)
{
    char header[512];
    snprintf(header, sizeof(header),
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n"
        "Set-Cookie: %s\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n",
        location,
        cookie,
        keep_alive ? "keep-alive" : "close",
        keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
    );
    send(client_fd, header, strlen(header), 0);
    log_simple(client_fd, "RESP 302 Set-Cookie + Location");
}

/* ======== Redirect fara cookie (ex: redirect la login) ======= */
void send_302_location(int client_fd, const char* location, int keep_alive)
{
    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n",
        location,
        keep_alive ? "keep-alive" : "close",
        keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
    );
    send(client_fd, header, strlen(header), 0);
    log_simple(client_fd, "RESP 302 Location");
}

void send_200_json(int client_fd, const char* json, int keep_alive)
{
    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n",
        strlen(json),
        keep_alive ? "keep-alive" : "close",
        keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
    );
    send(client_fd, header, strlen(header), 0);
    send(client_fd, json, strlen(json), 0);

    log_simple(client_fd, keep_alive ? "RESP 200 OK (json, keep-alive)" : "RESP 200 OK (json, close)");
}


// DENISA end---------------------------


// ======== Detectam cale nesigura (ca sa nu poata fi accesate fisierele sistemului) ==========
static void urldecode_path(const char *src, char *dest, size_t dest_sz)
{
    size_t di = 0;
    for (size_t si = 0; src[si] != '\0' && di + 1 < dest_sz; si++) {
        if (src[si] == '%' && isxdigit((unsigned char)src[si+1]) && isxdigit((unsigned char)src[si+2])) {
            char code[3] = { src[si+1], src[si+2], 0 };
            dest[di++] = (char)strtol(code, NULL, 16);
            si += 2;
        } else {
            dest[di++] = src[si];
        }
    }
    dest[di] = '\0';
}

static int is_path_unsafe(const char *raw_path)
{
    // extragem info de interes din "header-ul" http
    char decoded[2048];
    urldecode_path(raw_path, decoded, sizeof(decoded));

    // trebuie sa inceapa cu slash '/'
    if (decoded[0] != '/') return 1;

    // blocam backslash (\\)
    if (strchr(decoded, '\\') != NULL) return 1;

    // blocam traversarea prin directoare / foldere
    if (strstr(decoded, "..") != NULL) return 1;

    return 0;
}

// DENISA begin---------------------------------------

// ======== UTIL: extrage valoarea unui header (ex: Cookie, Authorization) ========
static int get_header_value(const char *headers, const char *name, char *out, size_t out_sz)
{
    if (!headers) return 0;
    const char *p = headers;
    size_t name_len = strlen(name);
    while (*p) {
        const char *line_end = strstr(p, "\r\n");
        if (!line_end) break;
        if (line_end == p) break; // linie goala
        if (strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t n = (size_t)(line_end - v);
            if (n >= out_sz) n = out_sz - 1;
            memcpy(out, v, n);
            out[n] = '\0';
            return 1;
        }
        p = line_end + 2;
    }
    return 0;
}

// ======== UTIL: extrage cookie din header Cookie (de ex SID=...) ========
static int get_cookie_value(const char *headers, const char *cookie_name, char *out, size_t out_sz)
{
    char cookie_hdr[1024];
    if (!get_header_value(headers, "Cookie", cookie_hdr, sizeof(cookie_hdr))) return 0;
    // cookie string: "SID=abcd; other=..."; cautam cookie_name=
    char *p = cookie_hdr;
    size_t keylen = strlen(cookie_name);
    while (*p) {
        while (*p == ' ') p++;
        if (strncasecmp(p, cookie_name, keylen) == 0 && p[keylen] == '=') {
            p += keylen + 1;
            char *end = strchr(p, ';');
            size_t n = end ? (size_t)(end - p) : strlen(p);
            if (n >= out_sz) n = out_sz - 1;
            memcpy(out, p, n);
            out[n] = '\0';
            return 1;
        }
        char *semi = strchr(p, ';');
        if (!semi) break;
        p = semi + 1;
    }
    return 0;
}

// ======== UTIL: extrage valoarea unui camp din body application/x-www-form-urlencoded ========
static void get_form_value(const char *body, const char *key, char *out, size_t out_sz)
{
    out[0] = '\0';
    if (!body || !key || out_sz == 0) return;

    size_t klen = strlen(key);
    const char *p = body;
    // cautam pattern "key=" dar asiguram ca preceda inceputul sau '&'
    while (p && *p) {
        const char *found = strstr(p, key);
        if (!found) break;
        // verificam ca imediat dupa key urmeaza '='
        if (found[klen] == '=') {
            // verificam ca e inceputul sau precedat de '&'
            if (found == body || *(found - 1) == '&') {
                const char *val = found + klen + 1;
                const char *end = strchr(val, '&');
                size_t n = end ? (size_t)(end - val) : strlen(val);
                if (n >= out_sz) n = out_sz - 1;
                memcpy(out, val, n);
                out[n] = '\0';
                return;
            }
        }
        p = found + 1;
    }
}

// ======== UTIL: decode base64 (simplu) ========
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static int base64_decode(const char *in, unsigned char *out, size_t *out_len) {
    size_t il = strlen(in);
    size_t i = 0, o = 0;
    int val=0, valb=-8;
    for (i = 0; i < il; ++i) {
        int c = in[i];
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) continue;
        val = (val<<6) + v;
        valb += 6;
        if (valb >= 0) {
            if (out) out[o] = (unsigned char)((val>>valb) & 0xFF);
            o++;
            valb -= 8;
        }
    }
    *out_len = o;
    return 0;
}

// ======== SESSIUNI: gaseste sesiune prin id (returneaza pointer sau NULL) ========
static session_t* session_find_by_id(const char *id)
{
    if (!id) return NULL;
    pthread_mutex_lock(&sessions_mutex);
    session_t *p = sessions_head;
    time_t now = time(NULL);
    while (p) {
        if (strcmp(p->id, id) == 0) {
            if (p->expiry >= now) {
                pthread_mutex_unlock(&sessions_mutex);
                return p;
            } else {
                // expirata -> o stergem (nu intoarcem pointer invalid)
                break;
            }
        }
        p = p->next;
    }
    pthread_mutex_unlock(&sessions_mutex);
    return NULL;
}

// ======== SESSIUNI: adauga sesiune (id, username) ========
static void session_add(const char *id, const char *username)
{
    session_t *s = malloc(sizeof(session_t));
    if (!s) return;
    strncpy(s->id, id, sizeof(s->id)-1);
    s->id[sizeof(s->id)-1] = '\0';
    strncpy(s->username, username, sizeof(s->username)-1);
    s->username[sizeof(s->username)-1] = '\0';
    s->expiry = time(NULL) + SESSION_TTL_SECONDS;

    pthread_mutex_lock(&sessions_mutex);
    // curatam expirate
    session_t **pp = &sessions_head;
    time_t now = time(NULL);
    while (*pp) {
        session_t *cur = *pp;
        if (cur->expiry < now) {
            *pp = cur->next;
            free(cur);
        } else {
            pp = &cur->next;
        }
    }
    s->next = sessions_head;
    sessions_head = s;
    pthread_mutex_unlock(&sessions_mutex);
}

// ======== SESSIUNI: sterge dupa id ========
static void session_remove_by_id(const char *id)
{
    pthread_mutex_lock(&sessions_mutex);
    session_t **pp = &sessions_head;
    while (*pp) {
        session_t *cur = *pp;
        if (strcmp(cur->id, id) == 0) {
            *pp = cur->next;
            free(cur);
            break;
        }
        pp = &cur->next;
    }
    pthread_mutex_unlock(&sessions_mutex);
}

// ======== UTIL: genereaza SID hex (din /dev/urandom sau rand fallback) ========
static void generate_session_id(char *out, size_t out_sz)
{
    unsigned char buf[32];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, sizeof(buf), f);
        fclose(f);
    } else {
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = rand() % 256;
    }
    static const char hex[] = "0123456789abcdef";
    size_t out_i = 0;
    for (size_t i = 0; i < sizeof(buf) && out_i + 2 < out_sz; i++) {
        out[out_i++] = hex[(buf[i] >> 4) & 0xF];
        out[out_i++] = hex[buf[i] & 0xF];
    }
    out[out_i] = '\0';
}

// ======== USERS: incarcare din users.txt (format username:password pe linie) ========
static void users_load_from_file(const char *path)
{
    pthread_mutex_lock(&users_mutex);
    // eliberam lista veche
    user_t *p = users_head;
    while (p) { user_t *n = p->next; free(p); p = n; }
    users_head = NULL;

    FILE *f = fopen(path, "r");
    if (!f) { pthread_mutex_unlock(&users_mutex); return; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        if (line[0] == '\0') continue;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *username = line;
        char *password = colon + 1;
        user_t *u = malloc(sizeof(user_t));
        if (!u) continue;
        strncpy(u->username, username, sizeof(u->username)-1);
        u->username[sizeof(u->username)-1] = '\0';
        strncpy(u->password, password, sizeof(u->password)-1);
        u->password[sizeof(u->password)-1] = '\0';
        u->next = users_head;
        users_head = u;
    }
    fclose(f);
    pthread_mutex_unlock(&users_mutex);
}

// ======== USERS: verifica credentiale (plain-text comparare) ========
static int users_check_credentials(const char *username, const char *password)
{
    pthread_mutex_lock(&users_mutex);
    user_t *p = users_head;
    while (p) {
        if (strcmp(p->username, username) == 0 && strcmp(p->password, password) == 0) {
            pthread_mutex_unlock(&users_mutex);
            return 1;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&users_mutex);
    return 0;
}

// CHECK Basic Auth: parsa Authorization: Basic ... si verifica utilizator
// Daca returneaza 1 => username valid gasit si scris in out_username; daca returneaza 0 => nu e valid/no header
static int check_basic_auth(const http_request_t *req, char *out_username, size_t out_sz)
{
    char auth_hdr[512];
    if (!get_header_value(req->headers, "Authorization", auth_hdr, sizeof(auth_hdr))) return 0;
    // auth_hdr: "Basic base64=="
    // Folosim un pointer pentru a nu modifica numele array-ului
    char *p = auth_hdr;
    while (*p == ' ') p++;
    if (strncasecmp(p, "Basic ", 6) != 0) return 0;
    const char *b64 = p + 6;
    unsigned char decoded[512];
    size_t dec_len = 0;
    base64_decode(b64, decoded, &dec_len);
    if (dec_len == 0) return 0;

    // decoded: "username:password" -- asiguram terminator
    if (dec_len >= sizeof(decoded)) dec_len = sizeof(decoded) - 1;
    decoded[dec_len] = '\0';
    char *colon = strchr((char*)decoded, ':');
    if (!colon) return 0;
    *colon = '\0';
    char *username = (char*)decoded;
    char *password = colon + 1;

    // verificam credentiale in users list
    users_load_from_file("users.txt");
    if (users_check_credentials(username, password)) {
        if (out_username && out_sz > 0) {
            strncpy(out_username, username, out_sz-1);
            out_username[out_sz-1] = '\0';
        }
        return 1;
    }
    return 0;
}

// DENISA end---------------------------------------


// =========== functii pentru tipurile de request ============

void handle_get(int client_fd, const http_request_t* req, int keep_alive){
    const char* path = req->path;
    if (is_path_unsafe(path)) {
        send_400(client_fd);
        log_simple(client_fd, "400 Bad Request (blocked directory traversal)");
        return;
    }
    
     //DENISA begin------------------------------------
     // Rute speciale API / user
    if (strcmp(path, "/api/comments") == 0) {
        // return JSON cu comentarii (implementare separată)
        handle_api_comments(client_fd, req, keep_alive);
        return;
    }
    if (strcmp(path, "/whoami") == 0) {
        // returnează username din sesiune sau 401
        handle_whoami(client_fd, req, keep_alive);
        return;
    }

    // Logout (sterge cookie si redirect la /)
    if (strcmp(path, "/logout") == 0) {
        const char *cookie = "SID=deleted; Path=/; Max-Age=0; HttpOnly";
        send_302_set_cookie_and_location(client_fd, cookie, "/", keep_alive);
        return;
    }

    // Pagina de login (formular simplu HTML) 
    if (strcmp(path, "/login") == 0) {
        const char *body =
            "<!doctype html>"
            "<html><head><meta charset='utf-8'><title>Login</title></head>"
            "<body style='font-family: Arial;'>"
            "<h2>Autentificare</h2>"
            "<form method='POST' action='/login'>"
            "Username: <input name='username' /><br/>"
            "Parola: <input name='password' type='password' /><br/>"
            "<button type='submit'>Login</button>"
            "</form>"
            "<p><a href='/'>Înapoi</a></p>"
            "</body></html>";
        send_200(client_fd, "text/html", body, keep_alive);
        return;
    }
    //DENISA end-----------------------------


    char fullpath[2048] = "default";
    
     // 3.1. Daca e doar "/", inlocuim cu pagina principala / default 
     if(strcmp(path, "/") == 0){
        strcpy(fullpath, "blog/index.html");
    }
    else{
        // 3.2. Daca e o cale mai lunga, o cautam in folderul /blog/....
        snprintf(fullpath, sizeof(fullpath), "blog%s", path);
    }

    printf("Full path: %s\n", fullpath);

    // 4. Deschidem fisierul
    FILE* file = fopen(fullpath, "r");
    if(file == NULL){
        // 4.1 Daca fisierul nu exista => eroare 404 Page Not Found
        send_404(client_fd, req->path);
        return;
    }
    else { // DENISA -aici imi zicea ca sa nu mai punem intr-un else si imi zice:
            //Dacă e HEAD vs GET: handler principal folosește funcția handle_head pentru HEAD,
            // dar aici rămânem la GET behavior (fisier + body)

        // 4.2 Aflam lungimea fisierului
        fseek(file, 0, SEEK_END);
        long content_length = ftell(file);
        fseek(file, 0, SEEK_SET);

        // 4.3 Alocam buffer pentru continut
        char *content = malloc(content_length + 1);
        if (content == NULL) {
            perror("eroare la malloc");
            fclose(file);
            close(client_fd);
            return;
        }
        fread(content, 1, content_length, file);
        content[content_length] = '\0';  

        // Afla tipul fisierului
        const char* mime = "text/html";
        if (strstr(path, ".css"))  mime = "text/css";
        if (strstr(path, ".js"))   mime = "application/javascript";
        if (strstr(path, ".png"))  mime = "image/png";
        if (strstr(path, ".jpg"))  mime = "image/jpeg";
    
        // 4.4 Trimitem raspunsul complet (header + body)
        send_200_raw(client_fd, mime, content, content_length, keep_alive);

        free(content);
        fclose(file);
    }
}

void urldecode(char *src, char *dest) {
    char *p = src;
    char code[3] = {0};
    while (*p) {
        if (*p == '+') {
            *dest++ = ' ';
        } else if (*p == '%' && isxdigit(*(p+1)) && isxdigit(*(p+2))) {
            code[0] = *(p+1);
            code[1] = *(p+2);
            *dest++ = (char) strtol(code, NULL, 16);
            p += 2;
        } else {
            *dest++ = *p;
        }
        p++;
    }
    *dest = '\0';
}

void handle_post(int client_fd, const http_request_t* req, int keep_alive) {
    const char* path = req->path; 
    const char* data_start = req->body;


    if (data_start == NULL || req->body_length == 0) {
        // DENISA - Pentru anumite POST-uri lipsa body este eroare
        // (pentru login/signup/submit-comment avem nevoie de body)
        fprintf(stderr, "POST fara body sau body gol.\n");
        send_400(client_fd);
        return;
    }

    //DENISA begin------------------------------
    // ----- Signup: /signup -----
    // Signup
    if (strcmp(path, "/signup") == 0) {
        char user_raw[512] = {0};
        char pass_raw[512] = {0};
        get_form_value(data_start, "username", user_raw, sizeof(user_raw));
        get_form_value(data_start, "password", pass_raw, sizeof(pass_raw));

        char username[512] = {0}, password[512] = {0};
        urldecode(user_raw, username);
        urldecode(pass_raw, password);

    if (strlen(username) == 0 || strlen(password) == 0) {
        send_400(client_fd);
        return;
    }

    // reincarcam users din fisier (asiguram consistenta)
    users_load_from_file("users.txt");

    // verificam daca exista deja user
    pthread_mutex_lock(&users_mutex);
    user_t *p = users_head;
    int exists = 0;
    while (p) {
        if (strcmp(p->username, username) == 0) { exists = 1; break; }
        p = p->next;
    }
    pthread_mutex_unlock(&users_mutex);

    if (exists) {
        const char *body = "{\"error\":\"user_exists\"}";
        send_200_json(client_fd, body, keep_alive);
        return;
    }

    // adaugam user in users.txt (append)
    FILE *f = fopen("users.txt", "a");
    if (!f) {
        perror("fopen users.txt");
        send_200_json(client_fd, "{\"error\":\"io\"}", keep_alive);
        return;
    }
    // scriem username:password + newline
    fprintf(f, "%s:%s\n", username, password);
    fflush(f);
    // optional: fsync pentru a forța scrierea pe disc
    fsync(fileno(f));
    fclose(f);

    // reincarcam lista in memorie
    users_load_from_file("users.txt");

    // cream sesiune si trimitem cookie+redirect
    char sid[65];
    generate_session_id(sid, sizeof(sid));
    session_add(sid, username);
    char cookie[256];
    snprintf(cookie, sizeof(cookie), "SID=%s; Path=/; HttpOnly; Max-Age=%d", sid, SESSION_TTL_SECONDS);
    send_302_set_cookie_and_location(client_fd, cookie, "/", keep_alive);
    return;
}

    // ----- Login: /login -----
    
    if (strcmp(path, "/login") == 0) {
        char user_raw[512] = {0};
        char pass_raw[512] = {0};
        get_form_value(data_start, "username", user_raw, sizeof(user_raw));
        get_form_value(data_start, "password", pass_raw, sizeof(pass_raw));

        char username[512] = {0}, password[512] = {0};
        urldecode(user_raw, username);
        urldecode(pass_raw, password);

    if (strlen(username) == 0 || strlen(password) == 0) {
        // login invalid input
        const char *body =
            "<html><body style='font-family:Arial;'>"
            "<h1>Login esuat</h1>"
            "<p>Username sau parola incorecte.</p>"
            "<p><a href='/login'>Incearca din nou</a></p>"
            "</body></html>";
        send_200(client_fd, "text/html", body, keep_alive);
        return;
    }

    // reincarcam lista de users (in caz ca s-a modificat)
    users_load_from_file("users.txt");

    if (users_check_credentials(username, password)) {
        char sid[65];
        generate_session_id(sid, sizeof(sid));
        session_add(sid, username);
        char cookie[256];
        snprintf(cookie, sizeof(cookie), "SID=%s; Path=/; HttpOnly; Max-Age=%d", sid, SESSION_TTL_SECONDS);
        send_302_set_cookie_and_location(client_fd, cookie, "/", keep_alive);
        return;
    } else {
        const char *body =
            "<html><body style='font-family:Arial;'>"
            "<h1>Login esuat</h1>"
            "<p>Username sau parola incorecte.</p>"
            "<p><a href='/login'>Incearca din nou</a></p>"
            "</body></html>";
        send_200(client_fd, "text/html", body, keep_alive);
        return;
    }
}

        // Submit comment (protejata) - accepta sesiune sau Basic Auth
    if (strcmp(path, "/submit-comment") == 0) {
        char username_saved[128] = {0};
        int authenticated = 0;

        // 1) verificam SID cookie
        char sid[128];
        if (get_cookie_value(req->headers, "SID", sid, sizeof(sid))) {
            session_t *s = session_find_by_id(sid);
            if (s) {
                strncpy(username_saved, s->username, sizeof(username_saved)-1);
                username_saved[sizeof(username_saved)-1] = '\0';
                authenticated = 1;
            } else {
                // sesiune expirata -> stergem (optional)
                session_remove_by_id(sid);
            }
        }

        // 2) daca nu avem sesiune, incercam Basic Auth
        if (!authenticated) {
            char ba_user[128];
            if (check_basic_auth(req, ba_user, sizeof(ba_user))) {
                strncpy(username_saved, ba_user, sizeof(username_saved)-1);
                username_saved[sizeof(username_saved)-1] = '\0';
                authenticated = 1;
            }
        }

        // 3) daca tot nu e autentificat, raspundem:
        if (!authenticated) {
            // Daca clientul accepta HTML (probabil browser), redirectam la /login
            char accept_hdr[256];
            if (get_header_value(req->headers, "Accept", accept_hdr, sizeof(accept_hdr))
                && strstr(accept_hdr, "text/html") != NULL) {
                send_302_location(client_fd, "/login", keep_alive);
                return;
            } else {
                // altfel trimitem 401 + WWW-Authenticate pentru Basic
                const char *body = "Unauthorized";
                char header[256];
                snprintf(header, sizeof(header),
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "WWW-Authenticate: Basic realm=\"Restricted\"\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: %s\r\n"
                    "%s"
                    "\r\n",
                    strlen(body),
                    keep_alive ? "keep-alive" : "close",
                    keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
                );
                send(client_fd, header, strlen(header), 0);
                send(client_fd, body, strlen(body), 0);
                log_simple(client_fd, "RESP 401 Unauthorized (submit-comment)");
                return;
            }
        }

        // 4) extragem message din body si salvam folosind username_saved
        char msg_raw[1200] = {0};
        sscanf(data_start, "username=%199[^&]&message=%1199[^\r\n]", msg_raw, msg_raw);
        if (strlen(msg_raw) == 0) sscanf(data_start, "message=%1199[^\r\n]", msg_raw);

        char message_dec[1200] = {0};
        urldecode(msg_raw, message_dec);

        FILE *f = fopen("blog/comments.txt", "a");
        if (!f) {
            perror("Eroare la deschiderea comments.txt");
            send_200(client_fd, "text/plain", "ERR", keep_alive);
            return;
        }
        fprintf(f, "%s|%s\n", username_saved, message_dec);
        fclose(f);

        send_200(client_fd, "text/plain", "OK", keep_alive);
        return;
    }

    //DENISA end ----------------------------

    printf("BODY = [%s]\n", data_start);

    char username[100] = {0};
    char message[1000] = {0};

    int matched = sscanf(data_start,
                         "username=%99[^&]&message=%999[^\r\n]",
                         username, message);
    //printf("matched = %d\n", matched);
    printf("Nume utilizator: %s\n", username);
    printf("Mesaj: %s\n", message);

    char username_dec[200];
    char message_dec[1200];

    urldecode(username, username_dec);
    urldecode(message, message_dec);

    FILE *f = fopen("blog/comments.txt", "a");  
    if (!f) {
        perror("Eroare la deschiderea comments.txt");
    } else {
        fprintf(f, "%s|%s\n", username_dec, message_dec);
        fclose(f);
        printf("Comentariu salvat in blog/comments.txt\n");
    }

    // raspuns simplu de success
    send_200(client_fd, "text/plain", "OK", keep_alive);
}

// DENISA begin--------------------------------

void handle_head(int client_fd, const http_request_t* req, int keep_alive) 
{
    const char* path = req->path;
    if (is_path_unsafe(path)) {
        send_400(client_fd);
        log_simple(client_fd, "400 Bad Request (blocked directory traversal) [HEAD]");
        return;
    }

    char fullpath[2048] = "default";
    if (strcmp(path, "/") == 0) {
        strcpy(fullpath, "blog/index.html");
    } else {
        snprintf(fullpath, sizeof(fullpath), "blog%s", path);
    }

    FILE* file = fopen(fullpath, "r");
    if (file == NULL) {
        send_404(client_fd, req->path);
        return;
    }

    // aflăm lungimea fisierului
    fseek(file, 0, SEEK_END);
    long content_length = ftell(file);
    fseek(file, 0, SEEK_SET);

    // detectăm mime (la fel ca GET)
    const char* mime = "text/html";
    if (strstr(path, ".css"))  mime = "text/css";
    if (strstr(path, ".js"))   mime = "application/javascript";
    if (strstr(path, ".png"))  mime = "image/png";
    if (strstr(path, ".jpg"))  mime = "image/jpeg";

    // trimitem doar header-ele
    send_200_headers(client_fd, mime, content_length, keep_alive);

    fclose(file);
}

/* ======== handler pentru OPTIONS - trimite Accept-urile (Allow) ======= */
void handle_options(int client_fd, const http_request_t* req, int keep_alive) {
    // Pentru moment trimitem 204 No Content + header Allow
    send_204_allow(client_fd, keep_alive);
}

void handle_api_comments(int client_fd, const http_request_t* req, int keep_alive)
{
    FILE *f = fopen("blog/comments.txt", "r");
    if (!f) {
        // nu exista -> trimitem empty array
        send_200_json(client_fd, "[]", keep_alive);
        return;
    }

    // Construim JSON simplu: [{"username":"...","message":"..."}, ...]
    // Atentie: nu facem escaping complet aici (pentru proiect educational e OK).
    size_t cap = 4096;
    char *json = malloc(cap);
    if (!json) { fclose(f); send_200_json(client_fd, "[]", keep_alive); return; }
    size_t len = 0;
    len += snprintf(json + len, cap - len, "[");

    char line[2048];
    int first = 1;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strlen(line) == 0) continue;
        char *sep = strchr(line, '|');
        if (!sep) continue;
        *sep = '\0';
        char *user = line;
        char *msg = sep + 1;

        // extindem buffer daca e necesar
        size_t need = strlen(user) + strlen(msg) + 64;
        if (len + need >= cap) {
            size_t newcap = cap * 2;
            char *nb = realloc(json, newcap);
            if (!nb) break;
            json = nb; cap = newcap;
        }
        if (!first) len += snprintf(json + len, cap - len, ",");
        // simplu-escape pentru ghilimele si backslash (minimal)
        // in proiect educational este suficient; pentru productie folosi librarie JSON
        for (char *p = msg; *p; ++p) if (*p == '"' || *p == '\\') { /* no-op here */ }
        len += snprintf(json + len, cap - len,
                        "{\"username\":\"%s\",\"message\":\"%s\"}",
                        user, msg);
        first = 0;
    }
    len += snprintf(json + len, cap - len, "]");
    fclose(f);

    send_200_json(client_fd, json, keep_alive);
    free(json);
}

// ======== whoami -> 200 JSON {username:...} sau 401 ========
void handle_whoami(int client_fd, const http_request_t* req, int keep_alive)
{
    char sid[128];
    if (!get_cookie_value(req->headers, "SID", sid, sizeof(sid))) {
        // 401 Unauthorized (no cookie)
        const char *body = "{\"error\":\"unauthenticated\"}";
        char header[256];
        snprintf(header, sizeof(header),
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: %s\r\n"
            "%s"
            "\r\n",
            strlen(body),
            keep_alive ? "keep-alive" : "close",
            keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
        );
        send(client_fd, header, strlen(header), 0);
        send(client_fd, body, strlen(body), 0);
        log_simple(client_fd, "RESP 401 whoami");
        return;
    }
    session_t *s = session_find_by_id(sid);
    if (!s) {
        const char *body = "{\"error\":\"unauthenticated\"}";
        char header[256];
        snprintf(header, sizeof(header),
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: %s\r\n"
            "%s"
            "\r\n",
            strlen(body),
            keep_alive ? "keep-alive" : "close",
            keep_alive ? "Keep-Alive: timeout=5, max=50\r\n" : ""
        );
        send(client_fd, header, strlen(header), 0);
        send(client_fd, body, strlen(body), 0);
        log_simple(client_fd, "RESP 401 whoami (no session)");
        return;
    }

    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\"}", s->username);
    send_200_json(client_fd, body, keep_alive);
}

// ======== NOU: POST /signup -> adauga in users.txt si face login (Set-Cookie) ========
void handle_signup(int client_fd, const http_request_t* req, int keep_alive)
{
    const char *data_start = req->body;
    if (data_start == NULL || req->body_length == 0) {
        send_400(client_fd);
        return;
    }

    char user_raw[200] = {0};
    char pass_raw[200] = {0};
    sscanf(data_start, "username=%199[^&]&password=%199s", user_raw, pass_raw);

    char username[200], password[200];
    urldecode(user_raw, username);
    urldecode(pass_raw, password);

    if (strlen(username) == 0 || strlen(password) == 0) {
        const char *body = "{\"error\":\"invalid_input\"}";
        send_200_json(client_fd, body, keep_alive);
        return;
    }

    // incarcam utilizatorii si verificam daca exista
    users_load_from_file("users.txt");
    if (users_check_credentials(username, password)) {
        // user exista cu aceeasi parola -> doar login
        char sid[65];
        generate_session_id(sid, sizeof(sid));
        session_add(sid, username);
        char cookie[256];
        snprintf(cookie, sizeof(cookie), "SID=%s; Path=/; HttpOnly; Max-Age=%d", sid, SESSION_TTL_SECONDS);
        send_302_set_cookie_and_location(client_fd, cookie, "/", keep_alive);
        return;
    }

    // verificam daca user deja exista cu alta parola
    pthread_mutex_lock(&users_mutex);
    user_t *p = users_head;
    int exists = 0;
    while (p) {
        if (strcmp(p->username, username) == 0) { exists = 1; break; }
        p = p->next;
    }
    pthread_mutex_unlock(&users_mutex);

    if (exists) {
        // user deja exista, dar parola diferita -> eroare
        const char *body = "{\"error\":\"user_exists\"}";
        send_200_json(client_fd, body, keep_alive);
        return;
    }

    // adaugam user in users.txt (append)
    FILE *f = fopen("users.txt", "a");
    if (!f) {
        perror("fopen users.txt");
        send_200_json(client_fd, "{\"error\":\"io\"}", keep_alive);
        return;
    }
    fprintf(f, "%s:%s\n", username, password);
    fclose(f);

    // reincarcam users si creem sesiune
    users_load_from_file("users.txt");
    char sid[65];
    generate_session_id(sid, sizeof(sid));
    session_add(sid, username);
    char cookie[256];
    snprintf(cookie, sizeof(cookie), "SID=%s; Path=/; HttpOnly; Max-Age=%d", sid, SESSION_TTL_SECONDS);
    send_302_set_cookie_and_location(client_fd, cookie, "/", keep_alive);
}


// DENISA end-------------------------------




// ======== Functii de citire header + body integral din request http, in caz de cereri mai mari =======
static long get_content_length_from_headers(const char *headers)
{
    if (!headers) return 0;

    const char *p = headers;
    while (*p) {
        const char *line_end = strstr(p, "\r\n");
        if (!line_end) break;

        // line: "Content-Length: 123"
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            p += 15;
            while (*p == ' ' || *p == '\t') p++;
            long v = strtol(p, NULL, 10);
            if (v < 0) v = 0;
            return v;
        }

        p = line_end + 2;
        if (p[0] == '\r' && p[1] == '\n') break;
    }

    return 0;
}

static int read_one_http_request(int client_fd, char **out_buf, int *out_len)
{
    *out_buf = NULL;
    *out_len = 0;

    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char*)malloc(cap + 1);
    if (!buf) return -1;

    int headers_done = 0;
    size_t header_end_index = 0;
    long content_length = 0;

    while (1) {
        if (len >= MAX_REQUEST_SIZE) { free(buf); return -2; }

        if (len + 1024 + 1 > cap) {
            size_t newcap = cap * 2;
            if (newcap > MAX_REQUEST_SIZE) newcap = MAX_REQUEST_SIZE;
            char *nb = (char*)realloc(buf, newcap + 1);
            if (!nb) { free(buf); return -1; }
            buf = nb;
            cap = newcap;
        }

        ssize_t r = recv(client_fd, buf + len, cap - len, 0);
        if (r < 0) {
            // timeout -> EAGAIN/EWOULDBLOCK
            if (errno == EAGAIN || errno == EWOULDBLOCK) { free(buf); return -3; }
            free(buf);
            return -1;
        }
        if (r == 0) { free(buf); return -4; } // client closed

        len += (size_t)r;
        buf[len] = '\0';

        if (!headers_done) {
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep) {
                headers_done = 1;
                header_end_index = (size_t)(sep - buf) + 4;

                char saved = buf[header_end_index];
                buf[header_end_index] = '\0';
                content_length = get_content_length_from_headers(buf);
                buf[header_end_index] = saved;

                if (content_length > MAX_BODY_SIZE) { free(buf); return -2; }

                size_t have_body = len - header_end_index;
                if ((long)have_body >= content_length) break;
            }
        } else {
            size_t have_body = len - header_end_index;
            if ((long)have_body >= content_length) break;
        }
    }

    *out_buf = buf;
    *out_len = (int)len;
    return 0;
}



static int header_equals_token(const char *headers, const char *name, const char *token_lower)
{
    // cauta "name: ...." (case-insensitive) pana la linia goala
    if (!headers) return 0;

    const char *p = headers;
    size_t name_len = strlen(name);

    while (*p) {
        const char *line_end = strstr(p, "\r\n");
        if (!line_end) break;

        // linie goala => stop
        if (line_end == p) break;

        if (strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            while (*v == ' ' || *v == '\t') v++;

            // verificam daca token exista in valoare (simplu)
            // ex: "keep-alive", "close"
            char tmp[256];
            size_t n = (size_t)(line_end - v);
            if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
            memcpy(tmp, v, n);
            tmp[n] = '\0';

            // lower-case pentru comparatie simpla
            for (size_t i = 0; tmp[i]; i++) tmp[i] = (char)tolower((unsigned char)tmp[i]);

            if (strstr(tmp, token_lower) != NULL) return 1;
            return 0;
        }

        p = line_end + 2;
    }

    return 0;
}

static int should_keep_alive(const http_request_t *req)
{
    int is_http11 = (strcmp(req->protocol, "HTTP/1.1") == 0);
    int is_http10 = (strcmp(req->protocol, "HTTP/1.0") == 0);

    if (is_http11) {
        // in HTTP/1.1 keep-alive e implicit
        // inchidem doar daca clientul cere explicit Connection: close
        if (header_equals_token(req->headers, "Connection", "close")) return 0;
        return 1;
    }

    if (is_http10) {
        // in HTTP/1.0 close e implicit
        // pastram doar daca clientul cere explicit Connection: keep-alive
        if (header_equals_token(req->headers, "Connection", "keep-alive")) return 1;
        return 0;
    }

    return 0;
}



// ============ functie pentru gestionare conexiune + requesturi ================
void handle_connection(int *client_socket){
    int client_fd = *client_socket;

    struct timeval tv;
    tv.tv_sec = 5;   // 5 sec idle
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));



    //char buffer[BUFFER_SIZE];
    int handled = 0;
    while(handled < MAX_REQ_PER_CONN )
    {
            char* buffer = NULL;
        
        int valRead = 0;
        // 1. CItim DIN socket IN buffer
        
        //int valRead = read(client_fd, buffer, BUFFER_SIZE - 1);
        int rr = read_one_http_request(client_fd, &buffer, &valRead);
        if (rr != 0) {
            if (rr == -3) {
                // idle timeout pe keep-alive (normal)
                log_simple(client_fd, "KA idle timeout -> closing");
            } else if (rr == -4) {
                // client a inchis conexiunea (normal)
                log_simple(client_fd, "Client closed connection");
            } else if (rr == -2) {
                // request prea mare
                send_400(client_fd); // sau varianta cu keep_alive=0
                log_simple(client_fd, "400 Bad Request (request too large)");
            } else {
                // eroare reala
                perror("read_one_http_request");
            }
        
            // iesim din loop si inchidem o singura data la final
            break;
        }

        // 2. DIN buffer extragem METODA (GET, POST, PUT...) CALEA si PROTOCOLUL HTTP.
        http_request_t req;
        if (parse_http_request(buffer, valRead, &req) != 0) {
            fprintf(stderr, "Request HTTP invalid.\n");
            send_400(client_fd);
            log_simple(client_fd, "400 Bad Request (parse_http_request failed)");
            close(client_fd);
            return;
        }

        int keep_alive = should_keep_alive(&req);

        log_request_line(client_fd, &req, 0, 0); // status 0 = doar “received”


        // 2.1. Stabilim prioritatea pe baza metodei / caii
        priority_t prio;

        // DENISA - am adaugat pentru head si options

        if (strcmp(req.method, "POST") == 0) {
            prio = PRIORITY_HIGH;
        } else if (strcmp(req.method, "GET") == 0 || strcmp(req.method, "HEAD") == 0) {
            prio = PRIORITY_MEDIUM;
        } else if (strcmp(req.method, "OPTIONS") == 0) {
            prio = PRIORITY_LOW;
        } else {
            prio = PRIORITY_LOW;
        }
    
        // 2.2. Afisam request + prioritate
        printf("[THREAD %lu] Request %s %s cu prioritatea %s (client fd = %d)\n",
            pthread_self(),
            req.method,
            req.path,
            priority_to_string(prio),
            client_fd);

        // 3. Verificam TIPUL de metoda

        // DENISA - am adaugat pt head si options

        if(strcmp(req.method, "GET") == 0){
            printf("Clientul a cerut: %s\n", req.path);
            handle_get(client_fd, &req, keep_alive);
        }
        else if (strcmp(req.method, "POST") == 0) {
            handle_post(client_fd, &req, keep_alive);
        }
        else if (strcmp(req.method, "HEAD") == 0) {
            handle_head(client_fd, &req, keep_alive);
        }
        else if (strcmp(req.method, "OPTIONS") == 0) {
            handle_options(client_fd, &req, keep_alive);
        }
        else{
            fprintf(stderr, "Metoda %s nu e suportata\n", req.method);
            send_501(client_fd, req.method);
        }
        
        free(buffer);
        handled++;

        if (!keep_alive) {
            log_simple(client_fd, "Connection: close requested -> closing");
            break;
        }
    }
    close(client_fd);
}


void* thread_function(void *arg){
    while (1) {
        queue_item_t item;

        pthread_mutex_lock(&mutex);
        while (queue_is_empty()) {
            pthread_cond_wait(&condition_var, &mutex);
        }
        item = dequeue();
        pthread_mutex_unlock(&mutex);
        
        if (item.client_socket != NULL) {
            //afisez prioritatea
            printf("[THREAD %lu] Execut request cu prioritatea %d pentru client %d\n",
                   pthread_self(),
                   item.priority,
                   *(item.client_socket));

            handle_connection(item.client_socket);

            free(item.client_socket); 
        }
    }
    return NULL;
}

int main(){

    // DENISA -----------
    // seed pentru fallback gen SID
    srand((unsigned int)time(NULL));

    // Incarcam utilizatorii din fisier users.txt (daca exista)
    users_load_from_file("users.txt");
    // DENISA end------------

    // Deschidem fisierul de log
    log_file = fopen("server.log", "a");
    if (!log_file) {
        perror("eroare fopen server.log");
        // nu iesim neaparat; serverul poate rula si fara log
    } else {
        setvbuf(log_file, NULL, _IOLBF, 0); // line-buffered (mai safe la crash)
    }


    // Cream threadu-urile ca sa se ocupe de viitoarele conexiuni
    for(int i = 0; i < THREAD_POOL_SIZE; i++){
        pthread_create(&thread_pool[i], NULL, thread_function, NULL);
    }
    // Cream un socket
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0); //AF = Address Family
    if(sock_fd < 0){
        perror("eroare la socket");
        exit(-1);
    }

    // Cream adresa pentru bind
    struct sockaddr_in adresaHost;
    int lenAdresa_host = sizeof(adresaHost);

    adresaHost.sin_family = AF_INET;
    adresaHost.sin_port = htons(PORT); //htons(host to network short) = translateaaza bitii in network byte order (big endian)
    adresaHost.sin_addr.s_addr = htonl(INADDR_ANY);

    // Cream adresa clientului
    struct sockaddr_in client_addr;
    int client_addrlen = sizeof(client_addr);

    // Permite reutilizarea portului imediat dupa inchiderea serverului anterior (pe scurt repornire)
    int enable = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    // Facem bind la socket (ii dam un nume la socket :) )
    if (bind(sock_fd, (struct sockaddr *)&adresaHost, lenAdresa_host) != 0){
        perror("eroare la bind");
        exit(-1);
    }

    // Ascultam pentru conexiuni
    if (listen(sock_fd, SOMAXCONN) != 0){ //SOmaxconn = nr max conexiuni, 128
        perror("eroare la listen");
        exit(-1);
    }
    printf("Server HTTP asculta pe portul %d\n", PORT);
    printf("Asteptam conexiune...\n");

    // Acceptam n-conexiuni
    for(;;){

        int newSock_fd = accept(sock_fd, (struct sockaddr *)&client_addr, (socklen_t *)&client_addrlen);
        
        if (newSock_fd < 0){
            perror("eroare la accept");
            continue;
        }

        // Afisam clientul conectat
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        char ip[INET_ADDRSTRLEN] = "unknown";
        int port = 0;

        if (getpeername(newSock_fd, (struct sockaddr *)&peer, &peer_len) == 0) {
            inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
            port = ntohs(peer.sin_port);
        }

        printf("[MAIN] Client connected: %s:%d (fd=%d)\n", ip, port, newSock_fd);

        // Obtinem adresa clientului
        int sockname = getsockname(newSock_fd, (struct sockaddr *)&client_addr, (socklen_t *)&client_addrlen);
        if(sockname < 0){
            perror("eroare getsockname");
            continue;
        }

        // Punem conexiunea undeva unde thread-urile sa o poata gasi (intr-o coada)
        int* pclient = malloc(sizeof(int));
        *pclient = newSock_fd;

        priority_t prio = PRIORITY_MEDIUM; // default, sau calculat in functie de metoda / path etc.

        pthread_mutex_lock(&mutex);
        enqueue(pclient, prio);
        pthread_cond_signal(&condition_var);
        pthread_mutex_unlock(&mutex);



        // int *pclient = malloc(sizeof(int));
        // *pclient = newSock_fd;
        // pthread_mutex_lock(&mutex);
        // enqueue(pclient);
        // pthread_cond_signal(&condition_var);
        // pthread_mutex_unlock(&mutex);

    }

    return 0;
}


