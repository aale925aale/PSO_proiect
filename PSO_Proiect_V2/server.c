#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "myqueue.h"

#define PORT 8080
#define BUFFER_SIZE 1024
#define THREAD_POOL_SIZE 20

pthread_t thread_pool[THREAD_POOL_SIZE];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_var = PTHREAD_COND_INITIALIZER;

void handle_connection(int *client_socket){
    int client_fd = *client_socket;
    char buffer[BUFFER_SIZE];

    char raspuns[] = "HTTP/1.0 200 OK\r\n"
                  "Server: webserver-c\r\n"
                  "Content-type: text/html\r\n\r\n"
                  "<html>hello, world</html>\r\n";

    
    int valRead = read(client_fd, buffer, BUFFER_SIZE);
    if(valRead < 0){
        perror("eroare la read");
    }

    printf("%s", buffer);

    int valWrite = write(client_fd, raspuns, strlen(raspuns));
    if(valWrite < 0){
        perror("eroare la write");
        exit(-1);
    }
    close(client_socket);
}


void* thread_function(void *arg){
    while(1){
        int* pclient;
        pthread_mutex_lock(&mutex);
        pthread_cond_wait(&pclient, &mutex);
        if( pclient = dequeue() == NULL) {
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


