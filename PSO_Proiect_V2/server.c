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

#define MAX_HEADER_SIZE (16 * 1024)
#define MAX_BODY_SIZE   (256 * 1024)
#define MAX_REQUEST_SIZE (MAX_HEADER_SIZE + MAX_BODY_SIZE)


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

void send_200(int client_fd, const char* content_type, const char* body) {
    // 200 = request procesat cu succes
    char header[256];

    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        content_type,
        strlen(body)
    );

    // trimite header-ul
    send(client_fd, header, strlen(header), 0);

    // trimite body
    send(client_fd, body, strlen(body), 0);

    log_simple(client_fd, "RESP 200 OK (text)");
}

void send_200_raw(int client_fd, const char* content_type, const char* data, size_t length)
{
    // 200 raw = pt fisiere binare (imagini, css, js...)
    char header[256];

    snprintf(header, sizeof(header),
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %zu\r\n"
    "Connection: close\r\n"
    "\r\n",
    content_type,
    length
    );

    send(client_fd, header, strlen(header), 0);
    send(client_fd, data, length, 0);

    char msg[256];
    snprintf(msg, sizeof(msg), "RESP 200 OK (raw) len=%zu type=%s", length, content_type);
    log_simple(client_fd, msg);

}



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


// =========== functii pentru tipurile de request ============

void handle_get(int client_fd, const http_request_t* req){
    const char* path = req->path;
    if (is_path_unsafe(path)) {
        send_400(client_fd);
        log_simple(client_fd, "400 Bad Request (blocked directory traversal)");
        return;
    }
    
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
    else {
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
        send_200_raw(client_fd, mime, content, content_length);

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

void handle_post(int client_fd, const http_request_t* req) {
    const char* path = req->path; 
    const char* data_start = req->body;


    if (data_start == NULL || req->body_length == 0) {
        fprintf(stderr, "POST fara body sau body gol.\n");
        send_400(client_fd);
        return;
    }

    printf("BODY = [%s]\n", data_start);

    char username[100] = {0};
    char message[1000] = {0};

    int matched = sscanf(data_start,
                         "username=%99[^&]&message=%999[^\r\n]",
                         username, message);
    printf("matched = %d\n", matched);
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
    send_200(client_fd, "text/plain", "OK");
}


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

static int read_full_http_request(int client_fd, char **out_buf, int *out_len)
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
        if (len >= MAX_REQUEST_SIZE) {
            free(buf);
            return -2; // too big
        }

        if (len + 1024 + 1 > cap) {
            size_t newcap = cap * 2;
            if (newcap > MAX_REQUEST_SIZE) newcap = MAX_REQUEST_SIZE;
            char *nb = (char*)realloc(buf, newcap + 1);
            if (!nb) { free(buf); return -1; }
            buf = nb;
            cap = newcap;
        }

        ssize_t r = read(client_fd, buf + len, cap - len);
        if (r < 0) { free(buf); return -1; }
        if (r == 0) break; // client closed

        len += (size_t)r;
        buf[len] = '\0';

        if (!headers_done) {
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep) {
                headers_done = 1;
                header_end_index = (size_t)(sep - buf) + 4;

                // parse Content-Length from headers region
                // temporarily null-terminate headers for easier scan
                char saved = buf[header_end_index];
                buf[header_end_index] = '\0';
                content_length = get_content_length_from_headers(buf);
                buf[header_end_index] = saved;

                if (content_length > MAX_BODY_SIZE) {
                    free(buf);
                    return -2; // too big
                }

                // if we already have body fully, stop
                size_t have_body = len - header_end_index;
                if ((long)have_body >= content_length) break;
            }
        } else {
            // headers already found, keep reading until body complete
            size_t have_body = len - header_end_index;
            if ((long)have_body >= content_length) break;
        }
    }

    *out_buf = buf;
    *out_len = (int)len;
    return 0;
}


// ============ functie pentru gestionare conexiune + requesturi ================
void handle_connection(int *client_socket){
    int client_fd = *client_socket;
    //char buffer[BUFFER_SIZE];
    char* buffer = NULL;
    
    int valRead = 0;
    // 1. CItim DIN socket IN buffer
    
    //int valRead = read(client_fd, buffer, BUFFER_SIZE - 1);
    int rr = read_full_http_request(client_fd, &buffer, &valRead);
    if (rr != 0) {
        if (rr == -2) {
            send_400(client_fd);
            log_simple(client_fd, "400 Bad Request (request too large)");
        } else {
            perror("eroare la read_full_http_request");
        }
        close(client_fd);
        return;
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

    log_request_line(client_fd, &req, 0, 0); // status 0 = doar “received”


    // 2.1. Stabilim prioritatea pe baza metodei / caii
    priority_t prio;

    if (strcmp(req.method, "POST") == 0) {
         prio = PRIORITY_HIGH;
     } else if (strcmp(req.method, "GET") == 0) {
           prio = PRIORITY_MEDIUM;
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
    if(strcmp(req.method, "GET") == 0){
        printf("Clientul a cerut: %s\n", req.path);
        handle_get(client_fd, &req);
    }
    else if (strcmp(req.method, "POST") == 0) {
           handle_post(client_fd, &req);
    }
    else{
        fprintf(stderr, "Metoda %s nu e suportata\n", req.method);
        send_501(client_fd, req.method);
    }

    free(buffer);
    close(*client_socket);
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


