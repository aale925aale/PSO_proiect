#include <stdlib.h>
#include "myqueue.h"

// Three separate queues: high, medium, low
static node_t* head_high = NULL;
static node_t* tail_high = NULL;

static node_t* head_medium = NULL;
static node_t* tail_medium = NULL;

static node_t* head_low = NULL;
static node_t* tail_low = NULL;

void queue_init(void) {
    head_high = tail_high = NULL;
    head_medium = tail_medium = NULL;
    head_low = tail_low = NULL;
}

void queue_destroy(void) {
    node_t* cur;

    // Free high priority queue
    cur = head_high;
    while (cur) {
        node_t* tmp = cur;
        cur = cur->next;
        free(tmp);
    }

    // Free medium priority queue
    cur = head_medium;
    while (cur) {
        node_t* tmp = cur;
        cur = cur->next;
        free(tmp);
    }

    // Free low priority queue
    cur = head_low;
    while (cur) {
        node_t* tmp = cur;
        cur = cur->next;
        free(tmp);
    }

    head_high = tail_high = NULL;
    head_medium = tail_medium = NULL;
    head_low = tail_low = NULL;
}

static void push_node(node_t** head, node_t** tail,
                      int* client_socket, priority_t priority) {
    node_t* new_node = (node_t*)malloc(sizeof(node_t));
    if (!new_node) {
        return;
    }
    new_node->client_socket = client_socket;
    new_node->priority = priority;   // setam prioritatea aici
    new_node->next = NULL;

    if (*tail == NULL) {
        *head = *tail = new_node;
    } else {
        (*tail)->next = new_node;
        *tail = new_node;
    }
}

static node_t* pop_node(node_t** head, node_t** tail) {
    if (*head == NULL)
        return NULL;

    node_t* tmp = *head;

    *head = (*head)->next;
    if (*head == NULL) {
        *tail = NULL;
    }

    return tmp; // nu mai dam free aici
}



void enqueue(int* client_socket, priority_t priority) {
    switch (priority) {
        case PRIORITY_HIGH:
            push_node(&head_high, &tail_high, client_socket, PRIORITY_HIGH);
            break;
        case PRIORITY_MEDIUM:
            push_node(&head_medium, &tail_medium, client_socket, PRIORITY_MEDIUM);
            break;
        case PRIORITY_LOW:
        default:
            push_node(&head_low, &tail_low, client_socket, PRIORITY_LOW);
            break;
    }
}


queue_item_t dequeue(void) {
    queue_item_t item;
    item.client_socket = NULL;
    item.priority = PRIORITY_LOW; // valoare default

    node_t* node = NULL;

    // incercam intai coada de high
    node = pop_node(&head_high, &tail_high);
    if (node != NULL) {
        item.client_socket = node->client_socket;
        item.priority = node->priority; // ar trebui sa fie PRIORITY_HIGH
        free(node);
        return item;
    }

    // apoi medium
    node = pop_node(&head_medium, &tail_medium);
    if (node != NULL) {
        item.client_socket = node->client_socket;
        item.priority = node->priority;
        free(node);
        return item;
    }

    // apoi low
    node = pop_node(&head_low, &tail_low);
    if (node != NULL) {
        item.client_socket = node->client_socket;
        item.priority = node->priority;
        free(node);
        return item;
    }

    // daca toate sunt goale, client_socket ramane NULL
    return item;
}

int queue_is_empty(void) {
    return (head_high == NULL &&
            head_medium == NULL &&
            head_low == NULL);
}








// #include "myqueue.h"
// #include <stdlib.h>

// node_t* head = NULL;
// node_t* tail = NULL;


// void enqueue(int* client_socket){
//     node_t* newNode = malloc(sizeof(node_t));
//     newNode->client_socket = client_socket;
//     newNode->next = NULL;

//     if(tail == NULL){
//         head = newNode;
//     }
//     else{
//         tail->next = newNode;
//     }
//     tail = newNode;
// }

// int* dequeue(){
//     if(head == NULL){
//         return NULL;
//     }
//     else{
//         int *result = head->client_socket;
//         node_t* temp = head;
//         head = head->next;
//         if(head == NULL) {tail = NULL;}
//         free(temp);
//         return result;
//     }
// }