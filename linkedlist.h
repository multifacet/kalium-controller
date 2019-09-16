#include <stdlib.h>
#include <unistd.h>

#define FALSE 0
#define TRUE 1
#define OK 2
#define ERROR -1
#define MEMORYFAIL -2

typedef struct list_node
{
  void* data;
  struct list_node *prev,*next;
}list_node,list;


typedef struct node Node, node_t;

struct node
{	
	// node_info_t node_info;
	int id;
	int ctr;
	int loop_cnt;
	int next_cnt;
	list_node* successors[20];
};

/*init an empty cyclic doubly linked list with header*/
list*  list_init();	
/*destory list*/				
void list_destroy(list *L);
/*get number of nodes(without header) in list*/
int list_length(list *L);
/*if the list is empty*/
int list_empty(list *L);

/*get the pointer of the node in pos,pos at least 1*/
list* list_get_pointer(list *L,int pos);
/*get the element of the node in pos,pos at least 1**/
void* list_get_element(list *L,int pos);
/*get the postion of given node*/
int list_get_index( list *L, list_node* pnode );

/*insert a node after the node in pos-1,the node's data is e */
int list_insert(list *L,int pos,void* e);
/*add a node at the end of list*/
int list_append(list *L,void* e);
/*remove node in pos*/
int list_remove(list *L,int pos);
