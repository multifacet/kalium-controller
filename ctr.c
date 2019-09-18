#include "msg.h"
#include "linkedlist.h"

using namespace rapidjson;
using namespace std;

static node_t* comm_graph;

static pthread_mutex_t lock_x;

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

list* guard_status;

static int debug_call_cnt = 20;

static char* policy_buf;



long int get_time(void) {
	
	struct timeval tv;

	gettimeofday(&tv,NULL);
	//return (((long int)tv.tv_sec)*1000)+(tv.tv_usec/1000);
	return (long int)1000000 * tv.tv_sec + tv.tv_usec;
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
	int eid;
	idx = kh_get(event_mapping_table, ptr_event_mapping_table, event_hash);
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

void init_comm_graph(char* fname) 
{
	policy_buf = (char*) calloc(1024 * 1024 * 1024, sizeof(char));

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


void register_guard(void* context, char_t* recv_msg, msg_str_buff_t* msg_buff)
{


	char* guard_id = recv_msg;

	// int index = find_guard_keys(comm_graph, 5, guard_id);


	// node_t* cur = comm_graph + index;

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


	// for (int i = 0; i < cur->prev_cnt; i++){
	// 	// printf("%s\n", cur->prev[i]->node_info.id);
	// 	memcpy(pos + (i + 1 ) * 96, keys_to_str(cur->prev[i]->node_info.keys), 96);

	// }

	// printf("keys sent %d, %d\n", body_len, strlen(msg_str));
	// print_hex_len(msg_str, MSG_HDR_LEN + body_len);
	// s_send (context, msg_hdr);

	msg_buff -> msg_str = msg_str;
	msg_buff -> msg_len = MSG_HDR_LEN + body_len;



	//       zmq_msg_t msg;
	// int rc = zmq_msg_init_data (&msg, msg_body, msg_len, my_free, NULL); 
	// assert (rc == 0);
	//       rc = zmq_msg_send (&msg, context, 0); 

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


void split_str(char* str, const char* sep, char* out[]){
	int i = 0;
	char *p = strtok (str, sep);
	while (p != NULL)
	{
	    out[i++] = p;
	    p = strtok (NULL, sep);
	}

}

list_node* find_guard_status(list* L, char* guard_id){

	list *p = L->next; 
	while(p != L) 
	{
		if (strcmp(guard_id, (char*)p->data) == 0) {
			return p;
		}
		p = p->next;
	}
	return NULL;
}

int make_policy(char* src, char* event, char* url)
{
	// printf("%s\n", recv_msg_copy.body);

	khiter_t k =  kh_get(policy_table, ptr_policy_table, src);
	int is_missing = (k == kh_end(ptr_policy_table));

	// printf("%s, %s, %s, %d\n", src, event, url, is_missing);

	if (is_missing){

		list* policy = list_init();
		khash_t(policy_table)* h_policy = (khash_t(policy_table)*) ptr_policy_table;
		kh_set(policy_table, h_policy, src, policy);
		policy-> data = (char*) malloc (5 * sizeof(char));
		memset(policy -> data, '\0', 5);
		strncpy((char*) policy->data, EVENT_GET, 4);
		// k =  kh_get(policy_table, ptr_policy_table, src);
		return POLICY_TABLE_INIT;
	}

	list* policy = kh_val(ptr_policy_table, k);


	if (strcmp((char*) policy->data, EVENT_DONE) == 0){

		return POLICY_TABLE_NOOP;
	}

	if (strcmp(event, EVENT_GET) == 0){

		return POLICY_TABLE_NOOP;
	}

	if (strcmp(event,  EVENT_END) == 0){
		// printf("%s, %s, %s, %d\n", src, event, url, is_missing);
		policy-> data = (char*) malloc (5 * sizeof(char));
		memset(policy -> data, '\0', 5);
		strncpy((char*) policy->data, EVENT_DONE, 4);
		return POLICY_TABLE_DONE;
	}
	else {
		// printf("%s, %s, %s, %d\n", src, event, url, is_missing);
		int url_len = strlen(url);
		event_t* e = (event_t*) malloc (sizeof(event_t));
		e -> res = (char*) malloc ((url_len + 1) * sizeof(char));
		e -> res[url_len] = '\0';
		e -> ename[4] = '\0';
		strncpy(e -> ename, event, 4);
		strncpy(e -> res, url, url_len); 

		list_append(policy, (void*)e);
		return POLICY_TABLE_UPDATE;
	}


}

const char* jsonify_policy(char* src){

	list* policy = kh_val(ptr_policy_table, kh_get(policy_table, ptr_policy_table, src));
	int p_len = list_length(policy);

	Document d;
	d.SetObject();

	Document::AllocatorType& allocator = d.GetAllocator();

	Value event_array(kArrayType);
	Value url_array(kArrayType);

	// printf("%d\n", p_len);

	for (int i = 1; i < p_len + 1; i ++ )
	{	
		event_t* e = (event_t*) list_get_element(policy, i);
		event_array.PushBack(Value(e -> ename, allocator) , allocator);
		url_array.PushBack(Value(e -> res, allocator) , allocator);
	}

	d.AddMember("event", event_array, allocator);
	d.AddMember("url", url_array, allocator);

	StringBuffer buffer;
	Writer<StringBuffer> writer(buffer);
	d.Accept(writer);

	return buffer.GetString();
}

	static int
get_monitor_event (void *monitor, int *value, char **address)
{
	// First frame in message contains event number and value
	zmq_msg_t msg;
	zmq_msg_init (&msg);
	if (zmq_msg_recv (&msg, monitor, 0) == -1)
		return -1; // Interrupted, presumably
	assert (zmq_msg_more (&msg));

	uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
	uint16_t event = *(uint16_t *) (data);
	if (value)
		*value = *(uint32_t *) (data + 2);

	// Second frame in message contains event address
	zmq_msg_init (&msg);
	if (zmq_msg_recv (&msg, monitor, 0) == -1)
		return -1; // Interrupted, presumably
	assert (!zmq_msg_more (&msg));

	if (address) {
		uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
		size_t size = zmq_msg_size (&msg);
		*address = (char *) malloc (size + 1);
		memcpy (*address, data, size);
		(*address)[size] = 0;
	}
	return event;
}



static void * worker_routine (void *context) 
{
	//  Socket to talk to dispatcher
	void *worker = zmq_socket (context, ZMQ_DEALER);
	zmq_connect (worker, "inproc://workers");


	void *monitor = zmq_socket (context, ZMQ_PAIR);
	zmq_connect (monitor, "inproc://monitor-client");

	int test_flag = 0;
	// zmq_pollitem_t items [] = { 
	// 	{ worker, 0, ZMQ_POLLIN, 0 },
	// 	{ monitor, 0, ZMQ_POLLIN, 0 }
	// };

	zmq_pollitem_t items [] = { 
		{ worker, 0, ZMQ_POLLIN, 0 },
		// { monitor, 0, ZMQ_POLLIN, 0 }
	};


	long int st = get_time();
	zmq_msg_t gid;
	zmq_msg_init (&gid);
	int send_flag = 0;

	while (1) {
		// long int cur_tm = get_time() - st;
		// printf("%d\n", cur_tm);
		zmq_poll (items, 1, -1);

		if (items [0].revents & ZMQ_POLLIN) {

			zmq_msg_t id;
			zmq_msg_t recv_frame;


			zmq_msg_init (&id);
			zmq_msg_init (&recv_frame);


			int rc1 = zmq_msg_recv (&id, worker, 0);
			int rc2 = zmq_msg_recv (&recv_frame, worker, 0);

			zmq_msg_copy (&gid, &id);

			char* buf = (char*) zmq_msg_data(&recv_frame);


			msg_t recv_msg = msg_parser(buf);
			char_t type = recv_msg.header.type;
			char_t action = recv_msg.header.action;




			char* msg_str;
			msg_str_buff_t msg_str_buff;


			switch (type){
				case TYPE_INIT:
					register_guard(worker, recv_msg.body, &msg_str_buff);
					log_info("guard registration");
					break;

				case TYPE_INFO:
					{

						FILE *fp;
						printf("get1: %ld\n", get_time());

						// fp = fopen("guard_start.log", "a+");
						// fprintf(fp, recv_msg_copy.body);
						// fprintf(fp, "\n");
						// fclose(fp);
						continue;
					}
				case TYPE_POLICY:
					{

						if (ACTION_POLICY_INIT == action){

							khiter_t k =  kh_get(policy_local_table, ptr_policy_local_table, recv_msg.body);
							int is_missing = (k == kh_end(ptr_policy_local_table));
							if (!is_missing){
								send_policy(worker, recv_msg.body, &msg_str_buff);
							}
							else {
								continue;
							}
						}					
					}
					break;

				case TYPE_EVENT:
					{	
						char* info[9];

						printf("!!!%s\n", recv_msg.body);
						split_str(recv_msg.body, ":", info);
						char* src = info[0];
						char* event = info[1];
						char* url = info[2];
						char* ip = info[3];
						char* port = info[4];
						char* method = info[5];
						char* has_body = info[6];
						char* _id = info[7];
						char* rid = info[8];
						int ret = make_policy(src, event, url);

						zmq_msg_t resp_msg;
						char* done = "done";
						int rc = zmq_msg_init_data (&resp_msg, done, strlen(done) , NULL, NULL); 


						rc = zmq_msg_send(&id, worker, ZMQ_SNDMORE);
						rc = zmq_msg_send(&resp_msg, worker, 0); 

						zmq_msg_close (&resp_msg);
						free(recv_msg.body);

						continue;

					}

				case TYPE_CHECK_STATUS:
					{

						printf("check status\n");
						list_node* p = find_guard_status(guard_status, recv_msg.body);

						khash_t(guard_sts_table)* h_sts_table = (khash_t(guard_sts_table)*) ptr_guard_sts_table;
						printf("check: %s\n", kh_get_str_val(guard_sts_table, h_sts_table, (char*)p->data));

						continue;

					}

				case TYPE_CHECK_EVENT:
					{

						// printf("event check\n");
						char* info[9];

						printf("aaa%s\n", recv_msg.body);
						split_str(recv_msg.body, ":", info);
						char* src = info[0];
						char* event = info[1];
						char* url = info[2];
						char* ip = info[3];
						char* port = info[4];
						char* method = info[5];
						char* has_body = info[6];
						char* _id = info[7];
						char* rid = info[8];
						int ret = make_policy(src, event, url);

						zmq_msg_t resp_msg;
						char* done = "done";

						check_resp(worker, done,  &msg_str_buff);
						break;


					}
				case TYPE_TEST:
					printf("test\n");
					continue;

				default:
					break;

			}


			zmq_msg_t resp_msg;
			// printf("ready to send %d\n", msg_str_buff.msg_len);
			int rc = zmq_msg_init_data (&resp_msg, msg_str_buff.msg_str, msg_str_buff.msg_len , NULL, NULL); 
			// assert (rc == 0);

			// printf("ready to send %d\n", msg_str_buff.msg_len);
			// int size = s_send_len (context, msg_body, 10 + msg_len);

			rc = zmq_msg_send(&id, worker, ZMQ_SNDMORE);
			rc = zmq_msg_send(&resp_msg, worker, 0); 
			// printf("send1, %s, %d\n", (char*) zmq_msg_data(&id), rc);

			zmq_msg_close (&resp_msg);


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
	strncpy(policy_name, argv[1], strlen(argv[1]));
	init_comm_graph(policy_name);
	log_info("init policy %s; local graphs for %d funcs", policy_name, kh_size(ptr_policy_local_table));


	guard_status = list_init();

	void *context = zmq_ctx_new ();

	/* Socket to talk to clients */
	void *ctr = zmq_socket (context, ZMQ_ROUTER);
	char conn_str[100];
	sprintf(conn_str, "tcp://*:%d", CTR_PORT);
	zmq_bind (ctr, conn_str);
	log_info("wait for guard: %s", conn_str);

	/* Socket to talk to workers */
	void *workers = zmq_socket (context, ZMQ_DEALER);
	zmq_bind (workers, "inproc://workers");
	log_info("start %d workers", worker_no);

	zmq_socket_monitor (ctr, "inproc://monitor-client", ZMQ_EVENT_ALL);

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

