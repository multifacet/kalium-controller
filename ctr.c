#include "msg.h"
#include "linkedlist.h"

using namespace rapidjson;
using namespace std;



// static pthread_mutex_t lock_x;

const int policy_table = 0;
const int policy_local_table = 1;
const int guard_sts_table = 2;
const int event_mapping_table = 3;

KHASH_MAP_INIT_STR(policy_table, list*)
KHASH_MAP_INIT_STR(policy_local_table, char*)
KHASH_MAP_INIT_STR(guard_sts_table, char*)
KHASH_MAP_INIT_INT64(event_mapping_table, int)

khash_t(policy_table)* ptr_policy_table = kh_init(policy_table);
khash_t(policy_local_table)* ptr_policy_local_table = kh_init(policy_local_table);
khash_t(guard_sts_table)* ptr_guard_sts_table = kh_init(guard_sts_table);
khash_t(event_mapping_table)* ptr_event_mapping_table = kh_init(event_mapping_table);


static list_node* ptr_curr_state;
static list_node* ptr_list_head;

/* do not handle multiple apps, only return default*/
char* get_app_name(){
	char* out = "default";
	return out;
}

unsigned long get_time(void) {
	
	struct timeval tv;

	gettimeofday(&tv,NULL);
	//return (((long int)tv.tv_sec)*1000)+(tv.tv_usec/1000);
	return (unsigned long)1000000 * tv.tv_sec + tv.tv_usec;
}

keys_t gen_key_pair()
{	
	keys_t key_pair;
	const struct uECC_Curve_t* curve = uECC_secp256r1();
	uECC_make_key(key_pair.key_pub, key_pair.key_priv, curve);
	return key_pair;
}

int load_policy(char* fname, char* buffer)
{

	FILE * f = fopen (fname, "rb");
	int len;

	if (f)
	{
		fseek (f, 0, SEEK_END);
		len = ftell (f);
		fseek (f, 0, SEEK_SET);
		fread (buffer, 1, len, f);
		fclose (f);
		return 1;
	}

	return 0;
}

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


char* get_local_policy(char* func_name)
{
	khiter_t idx;
	char* ptr;
	idx = kh_get(policy_local_table, ptr_policy_local_table, func_name);
	ptr = kh_value(ptr_policy_local_table, idx);
	return ptr;
}

void policy_init() {

	list_node* ptr = ptr_list_head->next;
	while (ptr != ptr_list_head) {
		node* nptr = (node*) ptr-> data;
		nptr->ctr = nptr->loop_cnt;
		ptr = ptr->next;
	}
	ptr_curr_state = ptr_list_head;
}


void init_comm_graph(char* fname) 
{
	char* policy_buf = (char*) calloc(1024 * 1024 * 1024, sizeof(char));
	memset(policy_buf, '\0', sizeof(policy_buf));
	load_policy(fname, policy_buf);


	Document doc;
	doc.Parse(policy_buf);
	Value& name = doc["NAME"];
	char* app_name = (char*) calloc(name.GetStringLength() + 1, sizeof(char));
	memcpy(app_name, name.GetString(), name.GetStringLength()); 


	Value& event_ids = doc["EVENTID"];
	khash_t(event_mapping_table)* h = (khash_t(event_mapping_table)*) ptr_event_mapping_table;

	for (SizeType i = 0; i < event_ids.Size(); i++) {
		Value& tmp = event_ids[i];
		
		unsigned long k = tmp["h"].GetInt64();
		int v = tmp["e"].GetInt();	
		
		int ret;
		khiter_t idx;
		idx = kh_put(event_mapping_table, h, k, &ret);
		kh_value(h, idx) = v;
	}

	
	list* graph = list_init();
	Value& g = doc["GLOBALGRAPH"];
	Value& ns = g["ns"];
	Value& es = g["es"];
	for (SizeType i = 0; i < ns.Size(); i++) {
		Value& node = ns[i];
		Node* tnode = (Node*) malloc(sizeof(struct node));;
		tnode->id = node["id"].GetInt();
		tnode->next_cnt = 0;
		tnode->loop_cnt = node["cnt"].GetInt();
		list_append(graph, (void*)tnode);
		// tnode-> successors = list_init();
	}

	for (SizeType i = 0; i < es.Size(); i++) {
		Value& dsts = es[i]["1"];
		int src = es[i]["0"].GetInt();
		node* p_ns = (node*)list_get_element(graph, src+1);
		for (SizeType j = 0; j < dsts.Size(); j++) {
			int dst = dsts[j].GetInt();
			if (dst != -1) {
				list* p_nd = (list*)list_get_pointer(graph, dst+1);
				// void* sr = ((node*)p_ns)->successors;
				p_ns -> successors[p_ns->next_cnt] = p_nd;
				p_ns -> next_cnt =  p_ns -> next_cnt + 1;
			}
			else {
				p_ns -> successors[p_ns->next_cnt] = graph;
				p_ns -> next_cnt =  p_ns -> next_cnt + 1;
			}
		}
		log_debug("%d, %d", p_ns->id, p_ns->next_cnt);
	}

	khash_t(policy_table)* h_global = (khash_t(policy_table)*) ptr_policy_table;
	kh_set(policy_table, h_global, app_name, graph);

	ptr_curr_state = graph;
	ptr_list_head = graph;


	Value& locals = doc["LOCALGRAPH"];
	Value& url = doc["URL"];
	Value& io = doc["IO"];
	Value& ip = doc["IP"];
	Value& ior = doc["IOR"];
	Value& netr = doc["NETR"];
	Document tmpl;
	tmpl.SetObject();
	Document::AllocatorType& allocator = tmpl.GetAllocator();
	tmpl.AddMember("URL", url, allocator);
	tmpl.AddMember("IO", io, allocator);
	tmpl.AddMember("IP", ip, allocator);
	tmpl.AddMember("IOR", ior.GetInt(), allocator);
	tmpl.AddMember("NETR", netr.GetInt(), allocator);

	khash_t(policy_local_table)* h_local = (khash_t(policy_local_table)*) ptr_policy_local_table;

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
	    
	 	char* func_name = (char*) calloc(_name.GetStringLength() + 1, sizeof(char));
		memcpy(func_name, _name.GetString(), _name.GetStringLength());
		char* local_policy = (char*) calloc(buffer.GetSize() + 1, sizeof(char));
		memcpy(local_policy, buffer.GetString(), buffer.GetSize());
	 	kh_set(policy_local_table, h_local, func_name, local_policy);
	}

}



unsigned long djb2hash(char *func_name, char* event, char* url, char* action)
{	
	int _len = strlen(func_name) + strlen(event) + strlen(url) + strlen(action) + 1;
	char* hash_input = (char*)calloc(_len, sizeof(char));
	snprintf(hash_input, _len, "%s%s%s%s", func_name, event, url, action);
    unsigned long hash = 5381;
    int c;

    while (c = *hash_input++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}


void my_free (void *data, void *hint)
{
	free (data);
}

bool check_policy(int event_id){


	khiter_t k;
	k =  kh_get(policy_table, ptr_policy_table, get_app_name());
	int is_missing = (k == kh_end(ptr_policy_table));
	if (is_missing){
		log_error("no policy found");
		return false;
	}

	list_node* ptr = ptr_curr_state;
	if (ptr == ptr_list_head) {
		policy_init();
		ptr_curr_state = ptr_curr_state-> next;
		ptr = ptr_curr_state;
	}
	
	node* nptr = (node*) ptr-> data;
	if ((nptr->ctr > 0) && (nptr->id == event_id)) {
		nptr->ctr -= 1;
		
		return true;
	}
	
	for (int i = 0; i < nptr->next_cnt; i++){
		list_node* next_ptr = nptr -> successors[i];
		node* next_d_ptr = (node*) next_ptr->data;

		if ((next_d_ptr->ctr > 0) && (next_d_ptr->id == event_id)) {
			next_d_ptr->ctr -= 1;
			ptr_curr_state = next_ptr;
			return true;
		}
	}

	return false;
}



void register_guard(void* context, char* recv_msg, msg_str_buff_t* msg_buff)
{


	char* guard_id = recv_msg;
	keys_t tmp_k  = gen_key_pair();
	int body_len = 32 + 64;

	header_t hdr_t = init_msg_header(TYPE_KEY_DIST, ACTION_TEST, body_len);
	char* msg_hdr = header_to_str(hdr_t);

	char* msg_str = (char*) calloc (MSG_HDR_LEN + body_len + 1, sizeof(char));
	memset(msg_str, '\0', MSG_HDR_LEN + body_len + 1);

	char* pos = msg_str;
	memcpy(pos, msg_hdr, MSG_HDR_LEN);
	pos = msg_str + MSG_HDR_LEN;
	memcpy(pos, keys_to_str(tmp_k), 96);

	msg_buff -> msg_str = msg_str;
	msg_buff -> msg_len = MSG_HDR_LEN + body_len;

}


void send_policy(void* context, char* recv_msg, msg_str_buff_t* msg_buff)
{

	char* guard_id = recv_msg;
	int rc;
	char* policy = get_local_policy(guard_id);

	log_info("ready to send policy %s", policy);

	int body_len = strlen(policy);
	header_t hdr_t = init_msg_header(TYPE_POLICY, ACTION_POLICY_ADD, body_len);
	char* msg_hdr = header_to_str(hdr_t);
	char* msg_str = (char*) calloc (MSG_HDR_LEN + body_len + 1, sizeof(char));
	memset(msg_str, '\0', MSG_HDR_LEN + body_len + 1);
	memcpy(msg_str, msg_hdr, MSG_HDR_LEN);
	memcpy(msg_str + MSG_HDR_LEN, policy, body_len);

	msg_buff -> msg_str = msg_str;
	msg_buff -> msg_len = MSG_HDR_LEN + body_len;

}


void check_resp(void* context, char* res, msg_str_buff_t* msg_buff)
{

	int body_len = strlen(res);
	header_t hdr_t = init_msg_header(TYPE_CHECK_RESP, ACTION_TEST, body_len);
	char* msg_hdr = header_to_str(hdr_t);
	char* msg_str = (char*) calloc (MSG_HDR_LEN + body_len + 1, sizeof(char));
	memset(msg_str, '\0', MSG_HDR_LEN + body_len + 1);
	memcpy(msg_str, msg_hdr, MSG_HDR_LEN);
	memcpy(msg_str + MSG_HDR_LEN, res, body_len);

	msg_buff -> msg_str = msg_str;
	msg_buff -> msg_len = MSG_HDR_LEN + body_len;

}

void send_to_guard(void* socket, zmq_msg_t id, char msg_type, char action, char* data)
{	

	zmq_msg_t msg;
	char* msg_str = "";
	if (data) {
		msg_str = msg_basic(msg_type, action, data);
	}
	zmq_msg_init_data(&msg, msg_str, strlen(msg_str), NULL, NULL); 
	zmq_msg_send(&id, socket, ZMQ_SNDMORE);
	zmq_msg_send(&msg, socket, 0); 
	zmq_msg_close (&msg);
}


void split_str(char* str, const char* sep, char* out[]){
	int i = 0;
	char *p = strtok (str, sep);
	while (p != NULL)
	{
	    out[i++] = p;
	    p = strtok (NULL, sep);
	}

}



static void * worker_routine (void *context) 
{
	//  Socket to talk to dispatcher
	void *worker = zmq_socket(context, ZMQ_DEALER);
	zmq_connect(worker, "inproc://workers");


	void *monitor = zmq_socket(context, ZMQ_PAIR);
	zmq_connect(monitor, "inproc://monitor-client");



	zmq_pollitem_t items [] = { 
		{ worker, 0, ZMQ_POLLIN, 0 },
		// { monitor, 0, ZMQ_POLLIN, 0 }
	};


	zmq_msg_t cid;
	zmq_msg_init(&cid);


	while (1) {
		zmq_poll (items, 1, -1);

		if (items [0].revents & ZMQ_POLLIN) {

			zmq_msg_t id;
			zmq_msg_t recv_frame;


			zmq_msg_init(&id);
			zmq_msg_init(&recv_frame);

			int rc1 = zmq_msg_recv(&id, worker, 0);
			int rc2 = zmq_msg_recv(&recv_frame, worker, 0);

			zmq_msg_copy(&cid, &id);

			char* buf = (char*) zmq_msg_data(&recv_frame);

			msg_t recv_msg = msg_parser(buf);
			char type = recv_msg.header.type;
			char action = recv_msg.header.action;

			switch (type){
				case TYPE_INIT: 
				{
					keys_t k_tmp  = gen_key_pair();
					char* k_str = keys_to_str(k_tmp);
					send_to_guard(worker, id, TYPE_KEY_DIST, ACTION_NOOP, k_str);
					log_info("guard registration");
					break;
				}
				case TYPE_POLICY:
					{

						if (ACTION_POLICY_INIT == action){

							khiter_t k =  kh_get(policy_local_table, ptr_policy_local_table, recv_msg.body);
							int is_missing = (k == kh_end(ptr_policy_local_table));
							if (!is_missing){
				
								char* policy = get_local_policy(recv_msg.body);
								send_to_guard(worker, id, TYPE_POLICY, ACTION_POLICY_ADD, policy);
							}
							else {
								log_error("cannot find policy");
							}
						}					
					}
					break;

				case TYPE_EVENT:
					{	
				
						log_info("event %s", recv_msg.body);

						char* info[9];
						split_str(recv_msg.body, ":", info);
						char event[EVENT_LEN+1] = {'\0'};
						strncpy(event, info[1], EVENT_LEN);

						unsigned ev_hash = djb2hash(info[0], info[1], info[2], info[3]);
						int ev_id = get_event_id(ev_hash);						
						check_policy(ev_id);

						send_to_guard(worker, id, NULL, NULL, NULL);

						free(recv_msg.body);

#ifdef DEBUG
						if (strncmp(EVENT_END, event, EVENT_LEN) == 0){
							log_info("test: get guard state");
							send_to_guard(worker, cid, TYPE_CHECK_STATUS, ACTION_CTR_REQ, "test");

						}

#endif
						continue;
					}

				case TYPE_CHECK_EVENT:
					{

						log_info("event %s", recv_msg.body);
						char* info[9];
						split_str(recv_msg.body, ":", info);
						unsigned ev_hash = djb2hash(info[0], info[1], info[2], info[3]);
						int ev_id = get_event_id(ev_hash);

						if (check_policy(ev_id)) {
							send_to_guard(worker, id, TYPE_CHECK_RESP, ACTION_TEST, "ALLOW");
						}
						else {
							send_to_guard(worker, id, TYPE_CHECK_RESP, ACTION_TEST, "DENY");
						}
						break;


					}
				/* example user commands */
				case TYPE_CHECK_STATUS:
					switch(action) {

						case ACTION_USER: /* from user */
							/* send TYPE_CHECK_STATUS + ACTION_CTR_REQ to guard */
						case ACTION_GD_RESP: /* from guard */
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
	* The ctr needs a dummy or real policy (call graph), 
	* use tools/gen_policy.py to create one 
	*/
	int worker_no = 10;
	char policy_name[64];
	char conn_str[100];
	strncpy(policy_name, argv[1], strlen(argv[1]));
	init_comm_graph(policy_name);
	log_info("init policy %s; local graphs for %d funcs", policy_name, kh_size(ptr_policy_local_table));

	void *context = zmq_ctx_new ();

	/* Socket to talk to the guards and the user */
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
		pthread_create (&worker, NULL, worker_routine, context);
	}
	
	/*  Connect work threads to client threads via a queue proxy */
	zmq_proxy (ctr, workers, NULL);

	/* We never get here, but clean up anyhow */
	zmq_close (ctr);
	zmq_close (workers);
	zmq_ctx_destroy (context);
	return 0;
}

