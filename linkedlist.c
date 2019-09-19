#include "linkedlist.h"

list *list_init()
{ 
	list* L;
  	L = (list*)malloc(sizeof(list_node));
  	if (L != NULL) {
  		L->next = L->prev = L;
  		return L;
  	}
  	else {
  		/*fprintf(stderr,"fail to  malloc memeory !\n");*/
  		return NULL;	
  	}
    
}

void list_destroy(list *L)
{ 
  	list *q, *p = L->next; 
  	while (p != L) {
    	q = p->next;
    	free(p);
    	p = q;
  	}
  	free(L);
  	L = NULL;
}

int list_empty (list *L)
{ 
  	if ((L->next == L) && (L->prev == L))
    	return TRUE;
  	else
    	return FALSE;
}

int list_length(list *L)
{ 
  	int count = 0;
  	list *p = L->next; 
  	while (p != L) {
    	count++;
    	p=p->next;
  	}
  	return count;
}

list *list_get_pointer(list *L, int pos)
{
	  int i;
  	list *p = L; 
  	if ((pos < 0) || (pos > list_length(L))) {
    	/*fprintf(stderr,"illeagal position !\n");*/
    	return NULL;
    }
  	for (i = 1; i <= pos; i++) {
    	p = p->next;
    }
  	return p;
}

void *list_get_element(list *L, int pos)
{ 
  	int i = 1; 
  	list *p = L->next;
  	if ((pos < 0) || (pos > list_length(L))) {
  		return NULL;	
  	}

  	while ((p != L) && (i != pos)) {
  		p = p->next;
  		i ++;
  	}
  	if ((p == L) || (i > pos)) {
    	return NULL;
    }
    return p->data;
}

int list_get_index(list *L, list_node *pnode)
{
  int index = 0;
	list *p = L;
	if ((L == NULL)) {
		return ERROR;
	}

	while ((p != pnode )) {
		p = p->next;
		index++;		
	}
	if (p == L) {
		return ERROR;
	}
	return index;
}

/*insert a node after the node in pos-1*/
int list_insert(list *L, int pos, void *e)
{ 
  	list *p, *tnode;

  	if ((pos < 1) || (pos > list_length(L) + 1)) {
  		return ERROR;
  	}
    
  	p = list_get_pointer(L, pos-1); 
  	if (!p) {
  		return ERROR;
  	}	
  	tnode = (list*)malloc(sizeof(list_node));
  	
    if (!tnode) {
  		return MEMORYFAIL;
  	}
  	
    tnode->data = e;
  	tnode->prev = p; 
  	tnode->next = p->next;
  	p->next->prev = tnode;
  	p->next = tnode;
  	return OK;
}

int list_append(list *L, void* e)
{ 
  	list *p, *tnode;
  	p = L->prev;	
  	tnode = (list*)malloc(sizeof(list_node));
  	
    if (!tnode) {
  		return MEMORYFAIL;
  	}

  	tnode->data = e;
  	p->next = tnode;
  	tnode->prev = p; 
  	tnode->next = L;
  	L->prev = tnode;
  	return OK;
}

int list_remove(list *L,int pos)
{ 
  	list *p;

  	if ((pos < 1) || (pos > list_length(L) + 1)) {
  		return ERROR;
  	}
  	p = list_get_pointer(L, pos);
  	p->prev->next = p->next;
  	p->next->prev = p->prev;
  	free(p);
  	return OK;
}

void list_swap_nodes(list_node *low, list_node *high)
{

	list_node *tmp = NULL;
	if (low->next == high) {			

		low->prev->next = high;
		high->prev = low->prev;			
		low->prev = high;			
		low->next = high->next;			
			
		high->next->prev = low;
		high->next = low;

		tmp = high;
		high = low;
		low = tmp;						
	} 
  else {							
		low->prev->next = high;
		low->next->prev = high;
			
		high->prev->next = low;
		high->next->prev = low;		

		tmp = low->prev;
		low->prev = high->prev;
		high->prev = tmp;
		
		tmp = low->next;
		low->next = high->next;
		high->next = tmp;
			
		tmp = high;
		high = low;
		low = tmp;			
	}	
}
