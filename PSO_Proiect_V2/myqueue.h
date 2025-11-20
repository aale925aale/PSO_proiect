#ifndef MYQUEUE_H_
#define MYQUEUE_H_

// Priority levels
typedef enum {
    PRIORITY_LOW = 0,
    PRIORITY_MEDIUM = 1,
    PRIORITY_HIGH = 2
} priority_t;

const char* priority_to_string(priority_t p) {
    switch (p) {
        case PRIORITY_HIGH:   return "HIGH";
        case PRIORITY_MEDIUM: return "MEDIUM";
        case PRIORITY_LOW:    return "LOW";
    }
    return "UNKNOWN";
}

// Nodul din coada
typedef struct node {
    struct node* next;
    int* client_socket;
    priority_t priority;
} node_t;

// Ce intoarce dequeue: socket + prioritate
typedef struct {
    int* client_socket;
    priority_t priority;
} queue_item_t;

void queue_init(void);
void queue_destroy(void);

// Enqueue primeste acum si prioritatea
void enqueue(int* client_socket, priority_t priority);

queue_item_t dequeue(void);

int queue_is_empty(void);

#endif




// #ifndef MYQUEUE_H_
// #define MYQUEUE_H_

// struct node{
//     struct node* next;
//     int* client_socket;
// };
// typedef struct node node_t;

// void enqueue(int *client_socket);
// int *dequeue();

// #endif
