#include "msg.h"
#include "linkedlist.h"

using namespace rapidjson;
using namespace std;



// static pthread_mutex_t lock_x;

const int policy_table = 0;
const int policy_local_table = 1;
const int guard_sts_table = 2;
const int event_mapping_table = 3;

/* Hash maps */
KHASH_MAP_INIT_STR(policy_table, list*) 
KHASH_MAP_INIT_STR(policy_local_table, char*)
KHASH_MAP_INIT_STR(guard_sts_table, char*)
KHASH_MAP_INIT_INT64(event_mapping_table, int)

khash_t(policy_table) *ptr_policy_table = kh_init(policy_table);
khash_t(policy_local_table) *ptr_policy_local_table = kh_init(policy_local_table);
khash_t(guard_sts_table) *ptr_guard_sts_table = kh_init(guard_sts_table);
khash_t(event_mapping_table) *ptr_event_mapping_table = kh_init(event_mapping_table);


static list_node *ptr_curr_state;
static list_node *ptr_list_head;

/* Get current timestamp in us */
unsigned long get_time(void) 
{
	
	struct timeval tv;
	gettimeofday(&tv,NULL);
	//return (((long int)tv.tv_sec)*1000)+(tv.tv_usec/1000);
	return (unsigned long )1000000 * tv.tv_sec + tv.tv_usec;
}

/* 
* Split a string based on the separator
* @str: Input string
* @sep: The separator e.g., "," and "#"
* @out: Storing the split results
*/
void split_str(char *str, const char *sep, char *out[])
{
	int i = 0;
	char *p = strtok(str, sep);
	while (p != NULL) {
	    out[i++] = p;
	    p = strtok(NULL, sep);
	}
}

/* Generate ecc key pairs */
keys_t gen_key_pair()
{	
	keys_t key_pair;
	const struct uECC_Curve_t *curve = uECC_secp256r1();
	uECC_make_key(key_pair.key_pub, key_pair.key_priv, curve);
	return key_pair;
}

/* Remove the specified char from a string */
void strip(char *str, char c) 
{
    char *pr = str, *pw = str;
    while (*pr) {
        *pw = *pr++;
        pw += (*pw != c);
    }
    *pw = '\0';
}


/* Do not handle multiple apps, only return default*/
char *get_app_name()
{
	char *out = (char *)"default";
	return out;
}


/* Read policy from a file */
int load_policy(char *fname, char *buffer)
{

	FILE *f = fopen(fname, "rb");
	int len;
	if (f) {
		fseek(f, 0, SEEK_END);
		len = ftell (f);
		fseek(f, 0, SEEK_SET);
		fread(buffer, 1, len, f);
		fclose(f);
		return 1;
	}

	return 0;
}

/* 
* Calculate djb2hash of a string 
* @args: The hash input is a concatenation of all arguments
* Return: Hash value in unsigned long
*/
unsigned long djb2hash(char *func_name, char *event, char *url, char *action)
{	
	int _len = strlen(func_name) + strlen(event) + strlen(url) + strlen(action) + 1;
	char *hash_input = (char *)calloc(_len, sizeof(char));
	snprintf(hash_input, _len, "%s%s%s%s", func_name, event, url, action);
    unsigned long hash = 5381;
    int c;
    while ((c = *hash_input++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

/* Get event id based on event hash */
int get_event_id(unsigned long event_hash)
{
	khiter_t idx;
	int is_missing;
	int eid = -1;
	idx = kh_get(event_mapping_table, ptr_event_mapping_table, event_hash);
	is_missing = (idx == kh_end(ptr_event_mapping_table));
	if (is_missing) return eid;
	eid = kh_value(ptr_event_mapping_table, idx);
	return eid;
}

/* Get the policy for a given function */
char* get_local_policy(char *func_name)
{
	khiter_t idx;
	char *ptr;
	idx = kh_get(policy_local_table, ptr_policy_local_table, func_name);
	ptr = kh_value(ptr_policy_local_table, idx);
	return ptr;
}

/* Reset the loop count of policy*/
void policy_init() {

	list_node *ptr = ptr_list_head->next;
	while (ptr != ptr_list_head) {
		node* nptr = (node *)ptr->data;
		nptr->ctr = nptr->loop_cnt;
		ptr = ptr->next;
	}
	ptr_curr_state = ptr_list_head;
}

/* Generate the graph policy */
void init_comm_graph(char* fname) 
{	
	char *policy_buf = (char *)calloc(MAX_POLICY_LEN, sizeof(char));
	memset(policy_buf, '\0', MAX_POLICY_LEN);
	load_policy(fname, policy_buf);


	Document doc;
	doc.Parse(policy_buf);
	Value& name = doc["NAME"];
	/* 
	* The values stored in khash need to be points (for string) or int
	* Shouldn't free them unless need modify or delete a policy
	*/
	char *app_name = (char *)calloc(name.GetStringLength() + 1, sizeof(char));
	memcpy(app_name, name.GetString(), name.GetStringLength()); 


	/* 
	* An event = function_name + client event + HTTP URL + HTTP operation
	* Event hash = djb2hash(event)
	* The policy generator should assign each event (hash) a unique ID
	* and record the mapping in the policy ["EVENTID"] field
	* The ctr stores event mapping in event_mapping_table when processing a policy
	*/
	Value& event_ids = doc["EVENTID"];
	khash_t(event_mapping_table) *h = (khash_t(event_mapping_table) *) ptr_event_mapping_table;

	for (SizeType i = 0; i < event_ids.Size(); i++) {
		Value& tmp = event_ids[i];
		unsigned long k = tmp["h"].GetInt64();
		int v = tmp["e"].GetInt();	
		int ret;
		khiter_t idx;
		idx = kh_put(event_mapping_table, h, k, &ret);
		kh_value(h, idx) = v;
	}

	/* Start to parse the global policy */
	list *graph = list_init();
	Value& g = doc["GLOBALGRAPH"];
	Value& ns = g["ns"];
	Value& es = g["es"];

	/* Create nodes and use a double linked list to store the graph*/
	for (SizeType i = 0; i < ns.Size(); i++) {
		Value& node = ns[i];
		Node* tnode = (Node *)malloc(sizeof(struct node));;
		tnode->id = node["id"].GetInt();
		tnode->next_cnt = 0;
		tnode->loop_cnt = node["cnt"].GetInt();
		list_append(graph, (void *)tnode);
		// tnode-> successors = list_init();
	}

	for (SizeType i = 0; i < es.Size(); i++) {
		Value& dsts = es[i]["1"];
		int src = es[i]["0"].GetInt();
		node* p_ns = (node *)list_get_element(graph, src+1);
		for (SizeType j = 0; j < dsts.Size(); j++) {
			int dst = dsts[j].GetInt();
			if (dst != -1) {
				list *p_nd = (list *)list_get_pointer(graph, dst+1);
				// void* sr = ((node*)p_ns)->successors;
				p_ns->successors[p_ns->next_cnt] = p_nd;
				p_ns->next_cnt =  p_ns -> next_cnt + 1;
			}
			else {
				p_ns->successors[p_ns->next_cnt] = graph;
				p_ns->next_cnt =  p_ns->next_cnt + 1;
			}
		}
		log_debug("%d, %d", p_ns->id, p_ns->next_cnt);
	}
	/*Store global policy/call graph in a table */
	khash_t(policy_table) *h_global = (khash_t(policy_table) *)ptr_policy_table;
	kh_set(policy_table, h_global, app_name, graph);

	ptr_curr_state = graph;
	ptr_list_head = graph;

	/* Store the policy (as a string) for each function */
	Value& locals = doc["LOCALGRAPH"];
	/*** We do not use the following policy in this demo ***/
	Value& url = doc["URL"]; /* URL whitelist */
	Value& io = doc["IO"]; /* IO whitelist */
	Value& ip = doc["IP"]; /* IP whitelist */
	Value& ior = doc["IOR"]; /* IO rate limits */
	Value& netr = doc["NETR"]; /* network rate limits*/
	Document tmpl;
	tmpl.SetObject();
	Document::AllocatorType& allocator = tmpl.GetAllocator();
	tmpl.AddMember("URL", url, allocator);
	tmpl.AddMember("IO", io, allocator);
	tmpl.AddMember("IP", ip, allocator);
	tmpl.AddMember("IOR", ior.GetInt(), allocator);
	tmpl.AddMember("NETR", netr.GetInt(), allocator);

	khash_t(policy_local_table) *h_local = (khash_t(policy_local_table) *)ptr_policy_local_table;

	for (SizeType i = 0; i < locals.Size(); i++) {
		Document d;
		Document::AllocatorType& allocator = d.GetAllocator();
		d.CopyFrom(tmpl, allocator);
		Value& policy = locals[i];
		Value& _name = policy["NAME"];
		d.AddMember("GRAPH", policy, allocator);
		StringBuffer buffer;
	    Writer<StringBuffer> writer(buffer);
	    d.Accept(writer);
	    
	 	char *func_name = (char *)calloc(_name.GetStringLength() + 1, sizeof(char));
		memcpy(func_name, _name.GetString(), _name.GetStringLength());
		char *local_policy = (char *)calloc(buffer.GetSize() + 1, sizeof(char));
		memcpy(local_policy, buffer.GetString(), buffer.GetSize());
	 	kh_set(policy_local_table, h_local, func_name, local_policy);
	}

}

/* Required free function for zmq calls. */
void my_free (void *data, void *hint)
{
	free (data);
}

/* Only for demo */
void policy_reset_test() {

	#ifdef DEBUG
	if ((((node *)ptr_curr_state->data)->ctr == 0) && 
		(ptr_curr_state->next == ptr_list_head)) {
		policy_init();
	}

	#endif 
	return;

}

bool check_policy(int event_id)
{
	khiter_t k;
	k =  kh_get(policy_table, ptr_policy_table, get_app_name());
	int is_missing = (k == kh_end(ptr_policy_table));
	if (is_missing) {
		log_error("no policy found");
		return false;
	}

	/* Checks if the event is the first event received*/
	list_node* ptr = ptr_curr_state;
	if (ptr == ptr_list_head) {
		policy_init();
		ptr_curr_state = ptr_curr_state->next;
		ptr = ptr_curr_state;
	}
	
	node *nptr = (node*)ptr->data;
	// log_info("%d, %d, %d", event_id, nptr->id, nptr->ctr);
	/* 
	* Check current node: if event id matches and loop counter is not zero
	* If event id does not match, check the successor nodes to find the match node
	* and proceed to that node
	*/
	if (nptr->id == event_id) {
		if (nptr->ctr > 0) {
			nptr->ctr -= 1;
			policy_reset_test();
			return true;
		}
		return false;
	}
	
	for (int i = 0; i < nptr->next_cnt; i++) {
		list_node *next_ptr = nptr->successors[i];
		node* next_d_ptr = (node *)next_ptr->data;

		if ((next_d_ptr->ctr > 0) && (next_d_ptr->id == event_id)) {
			next_d_ptr->ctr -= 1;
			ptr_curr_state = next_ptr;
			policy_reset_test();
			return true;
		}
	}

	return false;
}

/* 
* Send a message to the guard. Need to first select 
* the connection based on ID and then send the message 
*/
void send_to_guard(void *socket, zmq_msg_t id, char msg_type, char action, char *data)
{	

	zmq_msg_t msg;
	char *msg_str = (char *) EMPTY;
	if (data) msg_str = msg_basic(msg_type, action, data);
	zmq_msg_init_data(&msg, msg_str, strlen(msg_str), NULL, NULL); 
	zmq_msg_send(&id, socket, ZMQ_SNDMORE);
	zmq_msg_send(&msg, socket, 0); 
	zmq_msg_close (&msg);
}






void *worker_routine(void *context) 
{
	/* Socket to talk to dispatcher */
	void *worker = zmq_socket(context, ZMQ_DEALER);
	zmq_connect(worker, "inproc://workers");


	// void *monitor = zmq_socket(context, ZMQ_PAIR);
	// zmq_connect(monitor, "inproc://monitor-client");

	zmq_pollitem_t items [] = { 
		{ worker, 0, ZMQ_POLLIN, 0 },
		// { monitor, 0, ZMQ_POLLIN, 0 }
	};


	zmq_msg_t cid;
	zmq_msg_init(&cid);


	while (1) {
		zmq_poll(items, 1, -1);

		if (items[0].revents & ZMQ_POLLIN) {

			zmq_msg_t id; /* zmq generates an ID for each guard-ctr connection */
			zmq_msg_t recv_frame;


			zmq_msg_init(&id);
			zmq_msg_init(&recv_frame);

			/* 
			* The ID will be freed after calling zmq_msg_send 
			* If we want to send request to the guard again 
			* we need to store a copy of the ID
			*/
			zmq_msg_recv(&id, worker, 0);
			zmq_msg_recv(&recv_frame, worker, 0);
			zmq_msg_copy(&cid, &id);

			char *buf = (char *)zmq_msg_data(&recv_frame);
			log_info("Received Message");
			log_info("Content: %s", buf);

			msg_t recv_msg = msg_parser(buf);
			char type = recv_msg.header.type;
			char action = recv_msg.header.action;

			switch (type) {
				case TYPE_INIT: 
				{
					/* 
					* Send ECC keys to the guard. We used to use ECC to sign every
					* message but don't need it for now. Might bring this back later
					*/
					keys_t k_tmp  = gen_key_pair();
					char *k_str = keys_to_str(k_tmp);
					send_to_guard(worker, id, TYPE_KEY_DIST, ACTION_NOOP, k_str);
					log_info("guard registration");
					
					break;
				}
				case TYPE_POLICY:
					{
						/* Get the policy for the function and send it to the guard */
						if (ACTION_POLICY_INIT == action) {
							char *null_policy = "NULL";
							khiter_t k =  kh_get(policy_local_table, ptr_policy_local_table, recv_msg.body);
							int is_missing = (k == kh_end(ptr_policy_local_table));
							if (!is_missing){
								char *policy = get_local_policy(recv_msg.body);
								log_info("found policy for %s", recv_msg.body);
								send_to_guard(worker, id, TYPE_POLICY, ACTION_POLICY_ADD, policy);
							}
							else {
								log_error("cannot find policy");
								send_to_guard(worker, id, TYPE_POLICY, ACTION_NOOP, null_policy);
							}
						}					
					}
					break;

				case TYPE_EVENT: /* Simply record the event and update state */
					{	
				
						log_info("event %s", recv_msg.body);
						//char *info[9];
						//split_str(recv_msg.body, ":", info);
						//char event[EVENT_LEN+1] = {'\0'};
						//strncpy(event, info[1], EVENT_LEN);

						//unsigned ev_hash = djb2hash(info[0], info[1], info[2], info[3]);
						//int ev_id = get_event_id(ev_hash);					
						//check_policy(ev_id);
						/* Send nothing, just as an ACK */
						send_to_guard(worker, id, NULL, NULL, NULL);

						free(recv_msg.body);

#ifdef DEBUG
						/* Showcase push-like requests */
						/*if (strncmp(EVENT_END, event, EVENT_LEN) == 0) {
							log_info("test: get guard state");
							policy_init();
							send_to_guard(worker, cid, TYPE_CHECK_STATUS, ACTION_CTR_REQ, (char *)"test");

						}*/

#endif
						continue;
					}

				case TYPE_CHECK_EVENT:
					{

						/* 
						* The guard doesn't know what to do and ask the ctr
						* The ctr check its global policy and send the decision to the guard
						*/
						log_info("event %s", recv_msg.body);
						char *info[9];
						split_str(recv_msg.body, ":", info);
						unsigned ev_hash = djb2hash(info[0], info[1], info[2], info[3]);
						int ev_id = get_event_id(ev_hash);

						if (check_policy(ev_id)) {
							send_to_guard(worker, id, TYPE_CHECK_RESP, ACTION_TEST, (char *)"ALLOW");
						}
						else {
							send_to_guard(worker, id, TYPE_CHECK_RESP, ACTION_TEST, (char *)"DENY");
						}
						break;


					}
				/* Example user commands */
				case TYPE_CHECK_STATUS:
					switch (action) {

						case ACTION_USER: /* From user */
							/* Send TYPE_CHECK_STATUS + ACTION_CTR_REQ to guard */
						case ACTION_GD_RESP: /* From guard */
							log_info("get status info from guard %s", recv_msg.body);

					}
     				break;
	  
				case TYPE_USER_POLICY:
					break;

				default:
					break;

			}

			free(recv_msg.body);

		}
	}
	zmq_close (worker);
	return NULL;
}

int main(int argc, char const *argv[])

{
	log_set_level(LOG_INFO);
	/* 
	* The ctr needs a dummy or real policy (call graph)
	*/
	int worker_no = 140;
	char policy_name[64];
	char conn_str[100];
	memset(policy_name, 0, 64 * sizeof(char));
	memset(conn_str, 0, 100 * sizeof(char));

	strncpy(policy_name, argv[1], strlen(argv[1]));
	init_comm_graph(policy_name);
	log_info("init policy %s; local graphs for %d funcs", policy_name, kh_size(ptr_policy_local_table));

	void *context = zmq_ctx_new ();

	/* 
	* Socket to talk to the guards and the user
	*/
	void *ctr = zmq_socket(context, ZMQ_ROUTER);	
	sprintf(conn_str, "tcp://*:%d", CTR_PORT);
	zmq_bind (ctr, conn_str);
	log_info("wait for guard: %s", conn_str);

	/* Socket to talk to workers */
	void *workers = zmq_socket (context, ZMQ_DEALER);
	zmq_bind(workers, "inproc://workers");
	log_info("start %d workers", worker_no);

	// zmq_socket_monitor(ctr, "inproc://monitor-client", ZMQ_EVENT_ALL);

	/*  Launch pool of worker threads */
	int thread_nbr;
	for (thread_nbr = 0; thread_nbr < worker_no; thread_nbr++) {
		pthread_t worker;
		pthread_create(&worker, NULL, worker_routine, context);
	}
	
	/* Connect work threads to client threads via a queue proxy */
	zmq_proxy(ctr, workers, NULL);

	/* We never get here, but clean up anyhow */
	zmq_close(ctr);
	zmq_close(workers);
	zmq_ctx_destroy(context);
	return 0;
}

