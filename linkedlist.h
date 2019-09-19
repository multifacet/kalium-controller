/*
 * author: Liang Wang
 */
#include <stdlib.h>
#include <unistd.h>

#define FALSE 0
#define TRUE 1
#define OK 2
#define ERROR -1
#define MEMORYFAIL -2

typedef struct list_node
{
  void *data;
  struct list_node *prev,*next;
}list_node,list;


typedef struct node Node, node_t;

struct node
{	
	int id;
	int ctr;
	int loop_cnt;
	int next_cnt;
	list_node *successors[20];
};

/* Init an empty cyclic doubly linked list with header */
list *list_init();	
/* Destory list */				
void list_destroy(list *L);
/* Get number of nodes(without header) in list */
int list_length(list *L);
/* If the list is empty */
int list_empty(list *L);

/* Get the pointer of the node in pos,pos at least 1 */
list *list_get_pointer(list *L, int pos);
/* Get the element of the node in pos,pos at least 1 */
void *list_get_element(list *L, int pos);
/* Get the postion of given node */
int list_get_index(list *L, list_node* pnode);

/* Insert a node after the node in pos-1,the node's data is e */
int list_insert(list *L, int pos, void *e);
/* Add a node at the end of list */
int list_append(list *L, void *e);
/* Remove node in pos */
int list_remove(list *L, int pos);
