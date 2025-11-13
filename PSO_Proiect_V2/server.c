#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

#include "myqueue.h"

#define PORT 8080
#define BUFFER_SIZE 1024
#define THREAD_POOL_SIZE 20

pthread_t thread_pool[THREAD_POOL_SIZE];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

void handle_get(int client_fd, const char* path){
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
        char raspuns_404[] = "HTTP/1.0 404 Not Found\r\n"
                             "Server: webserver-c\r\n"
                             "Content-type: text/html\r\n\r\n"
                             "<html><body>404 Not Found</body></html>\r\n";
        write(client_fd, raspuns_404, strlen(raspuns_404));
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
    

        // 4.4 Construim header-ul
        char header[BUFFER_SIZE];
        snprintf(header, sizeof(header),
                 "HTTP/1.0 200 OK\r\n"
                 "Server: webserver-c\r\n"
                 "Content-type: %s\r\n"
                 "Content-Length: %ld\r\n\r\n",
                 mime, content_length);

        // 4.5 Trimitem header-ul
        write(client_fd, header, strlen(header));

        // 4.6 Trimitem conținutul
        write(client_fd, content, content_length);

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


void handle_post(int client_fd, char *buffer) {
    char path[1024] = "";
    char username[100] = {0};
    char message[1000] = {0};

    sscanf(buffer, "POST %1023s", path);

    char *data_start = strstr(buffer, "\r\n\r\n");
    if (!data_start) return;
    data_start += 4;

    printf("BODY = [%s]\n", data_start);

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

    // Aici salvam comentariile in fisier
    FILE *f = fopen("blog/comments.txt", "a");  
    if (!f) {
        perror("Eroare la deschiderea comments.txt");
    } else {
        fprintf(f, "%s|%s\n", username_dec, message_dec);
        fclose(f);
        printf("Comentariu salvat in blog/comments.txt\n");
    }

    const char *body = "OK";
    char response[256];
    int len_body = strlen(body);
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        len_body, body);

    write(client_fd, response, len);
}



void handle_connection(int *client_socket){
    int client_fd = *client_socket;
    char buffer[BUFFER_SIZE];
    
    // 1. CItim DIN socket IN buffer
    int valRead = read(client_fd, buffer, BUFFER_SIZE);
    if(valRead < 0){
        perror("eroare la read");
    }
    buffer[valRead] = '\0';

    // 2. DIN buffer extragem METODA (GET, POST, PUT...) CALEA si PROTOCOLUL HTTP.
    char method[8], path[1024] = "", protocol[32];
    sscanf(buffer, "%7s %1023s %31s", method, path, protocol); 

    // 3. Verificam TIPUL de metoda
    if(strcmp(method, "GET") == 0){
        printf("Clientul a cerut: %s\n", path);
        handle_get(client_fd, path);
    }
    else if (strcmp(method, "POST") == 0) {
        //aici functie de handle_post
        handle_post(client_fd, buffer);
    }
    else{
        printf("Metoda %s nu e suportata", method);
    }

    close(*client_socket);
}


void* thread_function(void *arg){
    while(1){
        int* pclient;
        pthread_mutex_lock(&mutex);
        pthread_cond_wait(&condition_var, &mutex);
        if( (pclient = dequeue()) == NULL) {
            pthread_cond_wait(&condition_var, &mutex);
            //try again
            pclient = dequeue();
       }
        pthread_mutex_unlock(&mutex);

        if(pclient != NULL){
            //AVem o conexiune
            handle_connection(pclient);
        }
    }
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
        int *pclient = malloc(sizeof(int));
        *pclient = newSock_fd;
        pthread_mutex_lock(&mutex);
        enqueue(pclient);
        pthread_cond_signal(&condition_var);
        pthread_mutex_unlock(&mutex);

    }

    return 0;
}


