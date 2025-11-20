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

#include "myqueue.h"

#define PORT 8080
#define BUFFER_SIZE 1024
#define THREAD_POOL_SIZE 20

pthread_t thread_pool[THREAD_POOL_SIZE];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;


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
}

void handle_get(int client_fd, const http_request_t* req){
    const char* path = req->path;
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


    if (!data_start) {
        fprintf(stderr, "POST fara body.\n");
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


void handle_connection(int *client_socket){
    int client_fd = *client_socket;
    char buffer[BUFFER_SIZE];
    
    // 1. CItim DIN socket IN buffer
    int valRead = read(client_fd, buffer, BUFFER_SIZE - 1);
    if(valRead < 0){
        perror("eroare la read");
        close(client_fd);
        return;
    }
    buffer[valRead] = '\0';

    // 2. DIN buffer extragem METODA (GET, POST, PUT...) CALEA si PROTOCOLUL HTTP.
    http_request_t req;
    if (parse_http_request(buffer, valRead, &req) != 0) {
        fprintf(stderr, "Request HTTP invalid.\n");
        send_400(client_fd);
        close(client_fd);
        return;
    }


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


