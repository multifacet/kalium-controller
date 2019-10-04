#include "msg.h"
#include "linkedlist.h"
#include <string>
#include <fstream>

using namespace rapidjson;
using namespace std;


pthread_mutex_t lock_x;

//name of the hash table
const int state_table = 0;
const int url_whitelist = 1;
const int ip_whitelist = 2;
const int io_whitelist = 3;
const int policy_table = 4;
const int event_mapping_table = 5;

KHASH_MAP_INIT_STR(state_table, int)
KHASH_MAP_INIT_STR(url_whitelist, int)
KHASH_MAP_INIT_STR(ip_whitelist, int)
KHASH_MAP_INIT_STR(io_whitelist, int)
KHASH_MAP_INIT_STR(policy_table, list*)
KHASH_MAP_INIT_INT64(event_mapping_table, int)

khash_t(state_table) *ptr_state_table = kh_init(state_table);
khash_t(io_whitelist) *ptr_io_whitelist = kh_init(io_whitelist);
khash_t(ip_whitelist) *ptr_ip_whitelist = kh_init(ip_whitelist);
khash_t(url_whitelist) *ptr_url_whitelist = kh_init(url_whitelist);
khash_t(policy_table) *ptr_policy_table = kh_init(policy_table);
khash_t(event_mapping_table) *ptr_event_mapping_table = kh_init(event_mapping_table);


static state_t guard_state; /* Store the states of the guard */

static int ior = 0; /* IO rate limits */
static int netr = 0; /* Requests rate limits */

static list_node *ptr_curr_state;
static list_node *ptr_list_head;

// const struct uECC_Curve_t* curve = uECC_secp256r1();

char *get_func_name(){
#ifdef DEBUG
	char *out = (char *)"test0";
	return out;
#else
	return getenv("AWS_LAMBDA_FUNCTION_NAME");
#endif
}

char *get_region_name(){
#ifdef DEBUG
	char *out = (char *)"AWS_EAST";
	return out;
#else
	return getenv("AWS_REGION");
#endif
}

void split_str(char *str, const char *sep, char *out[])
{
	int i = 0;
	char *p = strtok(str, sep);
	while (p != NULL) {
	    out[i++] = p;
	    p = strtok(NULL, sep);
	}

}


void strip(char *str, char c) 
{
    char *pr = str, *pw = str;
    while (*pr) {
        *pw = *pr++;
        pw += (*pw != c);
    }
    *pw = '\0';
}


/* 
* Parse the crgoup file in AWS lambda instance to extract assigned instance ID
* In non-AWS env the format of this file is different so we use "instid" instead
*/
void get_inst_id(char* inst_id)
{

	FILE *fp;
    int linecnt = 0;
    char line[512];

#ifdef DEBUG
    fp = fopen("instid", "r");
#else
	fp = fopen("/proc/self/cgroup", "r");
#endif	
	
    if (fp == NULL)
        exit(EXIT_FAILURE);
    
    /* parse cgroup file to extract instance id */
    while (fgets(line, sizeof(line), fp)) {
        linecnt += 1;
        if (linecnt != 8) continue;
        char *ids[3];
        const char *sep = "/";
        split_str(line, sep, ids);
        strncpy(inst_id, ids[2], 14);
        inst_id[14] = '\0';
    }

    fclose(fp);
}

unsigned long get_time(void) 
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (unsigned long )1000000 * tv.tv_sec + tv.tv_usec;
}

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



void my_free(void *data, void *hint)
{
	free (data);
}

void state_init()
{
	guard_state.start_time = get_time();
	guard_state.request_no = 0;
	guard_state.io_no = 0;
	guard_state.running_time = 0;

}

/* Example for showing how to check whitelists */
int lookup(const int h_name, char *key)
{	

	khiter_t k;
	int is_missing;
	switch (h_name) {

		case io_whitelist: 
			k =  kh_get(io_whitelist, ptr_io_whitelist, key);
			is_missing = (k == kh_end(ptr_io_whitelist));
			break;

		case ip_whitelist: 
			k =  kh_get(ip_whitelist, ptr_ip_whitelist, key);
			is_missing = (k == kh_end(ptr_ip_whitelist));
			break;

		case url_whitelist: 
			k =  kh_get(url_whitelist, ptr_url_whitelist, key);
			is_missing = (k == kh_end(ptr_url_whitelist));
			break;

		default:
			k = -1;
			break;
	}

	return !is_missing;
}


void key_init_req(void *socket, char *guard_id)
{

	char *msg_str = msg_init(guard_id);
	zmq_msg_t msg; 
	zmq_msg_init_data(&msg, msg_str, strlen(msg_str), my_free, NULL); 
	zmq_msg_send(&msg, socket, 0); 
	zmq_msg_close(&msg);

}



void key_init_handler(char* msg_body, int msg_body_len)
{
	/* Handle key here */
	return;
}

/* Send a message to the ctr */
void send_to_ctr(void *socket, char msg_type, char action, char *data)
{
	zmq_msg_t msg;
	char *msg_str = msg_basic(msg_type, action, data);
	zmq_msg_init_data(&msg, msg_str, strlen(msg_str), NULL, NULL); 
	zmq_msg_send(&msg, socket, 0); 
	zmq_msg_close(&msg);
}

/* Send a message to the runtime */
void send_to_client(void *socket, zmq_msg_t id, char *data)
{

	zmq_msg_t msg; 
	zmq_msg_init_data(&msg, data, strlen(data), NULL, NULL);
	zmq_msg_send(&id, socket, ZMQ_SNDMORE);
	zmq_msg_send(&msg, socket, 0); 
	zmq_msg_close(&msg);
}




void policy_init_handler(char *msg_body, int msg_body_len)
{

	khash_t(io_whitelist) *h_io = (khash_t(io_whitelist)*)ptr_io_whitelist;
	khash_t(ip_whitelist) *h_ip = (khash_t(ip_whitelist)*)ptr_ip_whitelist;
	khash_t(url_whitelist) *h_url = (khash_t(url_whitelist)*)ptr_url_whitelist;

	Document doc;
	doc.Parse(msg_body);

	ior = doc["IOR"].GetInt();
	netr = doc["NETR"].GetInt();


	Value& fs = doc["IO"];
	for (SizeType i = 0; i < fs.Size(); i++) {
		char *buf = (char *)calloc(fs[i].GetStringLength() + 1, sizeof(char));
		memcpy(buf, fs[i].GetString(), fs[i].GetStringLength()); 
		kh_set(io_whitelist, h_io, buf, 1);

	}


	Value& ips = doc["IP"];
	for (SizeType i = 0; i < ips.Size(); i++) {
		char *buf = (char *)calloc(ips[i].GetStringLength() + 1, sizeof(char));
		memcpy(buf, ips[i].GetString(), ips[i].GetStringLength()); 
		kh_set(ip_whitelist, h_ip, buf, 1);
	}


	Value& urls = doc["URL"];
	for (SizeType i = 0; i < urls.Size(); i++) {
		char *buf = (char *)calloc(urls[i].GetStringLength() + 1, sizeof(char));
		memcpy(buf, urls[i].GetString(), urls[i].GetStringLength()); 
		kh_set(url_whitelist, h_url, buf, 1);

	}

	

	Value& policy = doc["GRAPH"];
	Value& name = policy["NAME"];
	char *func_name = (char *) calloc(name.GetStringLength() + 1, sizeof(char));
	memcpy(func_name, name.GetString(), name.GetStringLength()); 
	Value& event_ids = policy["EVENTID"];
	khash_t(event_mapping_table) *h = (khash_t(event_mapping_table) *)ptr_event_mapping_table;


	for (SizeType i = 0; i < event_ids.Size(); i++) {
		Value& tmp = event_ids[i];
		unsigned long k = tmp["h"].GetInt64();
		int v = tmp["e"].GetInt();
		int ret;
		khiter_t idx;
		idx = kh_put(event_mapping_table, h, k, &ret);
		kh_value(h, idx) = v;

	}

	

	list *graph = list_init();
	Value& ns = policy["ns"];
	Value& es = policy["es"];


	for (SizeType i = 0; i < ns.Size(); i++) {
		
		Value& node = ns[i];
		Node* tnode = (Node *) malloc(sizeof(struct node));;
		tnode->id = node["id"].GetInt();
		tnode->next_cnt = 0;
		tnode->loop_cnt = node["cnt"].GetInt();
		list_append(graph, (void *)tnode);
	}

	for (SizeType i = 0; i < es.Size(); i++) {
		Value& dsts = es[i]["1"];
		int src = es[i]["0"].GetInt();
		node *p_ns = (node*)list_get_element(graph, src+1);
		for (SizeType j = 0; j < dsts.Size(); j++) {
			int dst = dsts[j].GetInt();

			if (dst != -1) {
				list *p_nd = (list *)list_get_pointer(graph, dst+1);
				p_ns->successors[p_ns->next_cnt] = p_nd;
				p_ns->next_cnt = p_ns->next_cnt + 1;
			}
			else {

				p_ns->successors[p_ns->next_cnt] = graph;
				p_ns->next_cnt =  p_ns->next_cnt + 1;
			}
			;
		}

	}

	khash_t(policy_table) *h_policy = (khash_t(policy_table) *)ptr_policy_table;
	kh_set(policy_table, h_policy, func_name, graph);

	ptr_curr_state = graph;
	ptr_list_head = graph;

}



void policy_init() {

	list_node *ptr = ptr_list_head->next;
	while (ptr != ptr_list_head) {
		node *nptr = (node *)ptr->data;
		nptr->ctr = nptr->loop_cnt;
		ptr = ptr->next;
	}
	ptr_curr_state = ptr_list_head;
}



bool check_policy(int event_id){

	khiter_t k;
	k =  kh_get(policy_table, ptr_policy_table, get_func_name());
	int is_missing = (k == kh_end(ptr_policy_table));
	if (is_missing){
		log_error("no policy found");
		return false;
	}

	
	list_node *ptr = ptr_curr_state;
	if (ptr == ptr_list_head) {
		policy_init();
		ptr_curr_state = ptr_curr_state->next;
		ptr = ptr_curr_state;
	}
	
	node *nptr = (node *)ptr->data;
	// log_info("%d, %d, %d", event_id, nptr->id, nptr->ctr);

	if (nptr->id == event_id) {
		if (nptr->ctr > 0) {
			nptr->ctr -= 1;
			return true;
		}
		return false;
	}
	
	for (int i = 0; i < nptr->next_cnt; i++){
		list_node *next_ptr = nptr->successors[i];
		node *next_d_ptr = (node *)next_ptr->data;

		if ((next_d_ptr->ctr > 0) && (next_d_ptr->id == event_id)) {
			next_d_ptr->ctr -= 1;
			ptr_curr_state = next_ptr;
			return true;
		}
	}
	return false;
}





int main(int argc, char const *argv[])
{

	state_init();
	void *context = zmq_ctx_new();
	void *updater = zmq_socket(context, ZMQ_DEALER); /* Socket for get messages from the ctr */
	void *listener = zmq_socket(context, ZMQ_STREAM); /* Socket for get messages from the runtime */
	/* Socket for monitoring disk activity. Don't need it anymore */
	// void *backend = zmq_socket(context, ZMQ_ROUTER); 

	char conn_str[100];
	char identity [128];
	char *guard_id = get_func_name(); /* Function name */

	memset(identity, '\0', sizeof(identity));
	sprintf(identity, "%s%ld", guard_id, get_time());
	strip(identity, '-');

	char rid[16]; /* Lambda instance ID */
	memset(rid, '\0', sizeof(rid));
	get_inst_id(rid);


	zmq_setsockopt(updater, ZMQ_IDENTITY, identity, sizeof(identity));
	sprintf(conn_str, "tcp://%s:%d", CTR_IP, CTR_PORT);
  	log_info("connect to ctr: %s", conn_str);
	zmq_connect(updater, conn_str);

	// zmq_bind(backend, "inproc://diskmonitor");
	// log_info("start disk monitor");

	sprintf(conn_str, "tcp://*:%d", GUARD_PORT);
	zmq_bind(listener, conn_str);
	log_info("wait for function: %s", conn_str);


	zmq_pollitem_t items [] = { 
		{ updater, 0, ZMQ_POLLIN, 0 }, 
		{ listener, 0, ZMQ_POLLIN, 0 }, 
		// { backend, 0, ZMQ_POLLIN, 0 }, 
	};


	key_init_req(updater, guard_id);

	log_info("register to ctr");
	zmq_msg_t cid;

	while (1) {
		zmq_poll (items, 2, -1);

		if (items[0].revents & ZMQ_POLLIN) {
			
			zmq_msg_t buf;
			int msg_size;

			zmq_msg_init(&buf);
			zmq_msg_recv(&buf, updater, 0);

			msg_size = zmq_msg_size(&buf);
			if (msg_size <= 1) continue;

			msg_t recv_msg = msg_parser((char *)zmq_msg_data(&buf));
			char type = recv_msg.header.type;
			char action = recv_msg.header.action;
			


			switch (type) {

				case TYPE_KEY_DIST:
				{
					key_init_handler(recv_msg.body, strtol(recv_msg.header.len, NULL, 16));
					/* Ask for policy*/
					send_to_ctr(updater, TYPE_POLICY, ACTION_POLICY_INIT, guard_id);
					break;

				}

				case TYPE_POLICY:
				{
					if (ACTION_POLICY_ADD == action) {
						policy_init_handler(recv_msg.body, strtol(recv_msg.header.len, NULL, 16));
						log_info("finish registration; get policy");
					}
					break;
				}

				case TYPE_CHECK_RESP:
				{
					log_info("get check resp %s", recv_msg.body);
					send_to_client(listener, cid, recv_msg.body);
					break;

				}
				case TYPE_CHECK_STATUS: /* Showcase asking the ctr for decision */
				{

					log_info("send status to ctr");
					guard_state.running_time = get_time() - guard_state.start_time;
					int a = snprintf(NULL, 0, "%d", guard_state.request_no);
					int b = snprintf(NULL, 0, "%lu", guard_state.running_time);
					char buf[a+b+2] = {'\0'};
					sprintf(buf, "%d:%lu", guard_state.request_no,  guard_state.running_time);
					send_to_ctr(updater, TYPE_CHECK_STATUS, ACTION_GD_RESP, buf);
					break;
				}
				case TYPE_TEST:
					break;
				default:
					break;
			}


		}
		if (items[1].revents & ZMQ_POLLIN) {
			
			guard_state.request_no += 1;

			
			zmq_msg_t buf;
			int msg_size;

    		/* 
			* The event recvied from function contain three parts
			* Type: first 4 bytes of the string indicate the action of the function
			* Meta: URL + method + IP + port + if event has data + unique ID
			* Data: Data in the event 
			*/ 
			zmq_msg_init(&cid);
			zmq_msg_init(&buf);

			zmq_msg_recv(&cid, listener, 0);
			zmq_msg_recv(&buf, listener, 0);

			msg_size = zmq_msg_size(&buf);

			if (msg_size <= 1) continue;

			char *tmp = (char *)zmq_msg_data(&buf);
			char event[EVENT_LEN+1] = {'\0'};
			strncpy(event, tmp, EVENT_LEN);
				
			char* body = tmp + EVENT_LEN + 1;
			body[msg_size - EVENT_LEN - 1] = '\0';


    		Document d;
    		d.Parse(body);

    		if (strncmp(EVENT_CHECK, event, EVENT_LEN) == 0) {
    			
				send_to_client(listener, cid, guard_id);
				send_to_ctr(updater, TYPE_CHECK_STATUS, ACTION_NOOP, guard_id);
				
				continue;	
			}

    		if (!d.IsObject()) {
    			log_error("message is not an valid json object!");
    			char error_info[] = "no object";
    			send_to_client(listener, cid, error_info);
    			
 			}
 			else if (!d.HasMember("meta")){
 				log_error("message does not has the meta field!");
 				char error_info[] = "no meta";
 				send_to_client(listener, cid, error_info);
 			}	

    		else {

    			char *meta;
    			char *out;
				Value& meta_t = d["meta"]; 

				/* The guard should extract data as a string. Not shown in this demo*/
				// char *data;
				// Value& data_t = d["data"];   

				meta = (char *)calloc(strlen(meta_t.GetString()) + 1, sizeof(char));
				strncpy(meta, meta_t.GetString(), strlen(meta_t.GetString()));

				out = (char *)calloc(strlen(meta) + strlen(guard_id) + strlen(event) + strlen(rid) + 4, sizeof(char));    
				sprintf(out, "%s:%s:%s:%s", guard_id, event, meta, rid);
				
				/* 
				* 0 --> url; 1 --> method; 2 --> ip; 3 --> port; 
				* 4 --> has_body; 5 --> request id
				*/
				char *info[6];
				split_str(meta, ":", info);

				unsigned ev_hash = djb2hash(guard_id, event, info[0], info[1]);
				int ev_id = get_event_id(ev_hash);


				if (strncmp(EVENT_GET, event, EVENT_LEN) == 0) {
					
					send_to_ctr(updater, TYPE_CHECK_EVENT, ACTION_NOOP, out);
					
				}

				else if (strncmp(EVENT_END, event, EVENT_LEN) == 0) {
					policy_init();
					send_to_client(listener, cid, (char *)EMPTY);
					send_to_ctr(updater, TYPE_EVENT, ACTION_NOOP, out);
					
				}

				else if ((strncmp(EVENT_SEND, event, EVENT_LEN) == 0) || 
					(strncmp(EVENT_RESP, event, EVENT_LEN) == 0)) {
				   
					
					if (check_policy(ev_id)) {
						
						char dec[] = "ALLOW"; 
						send_to_client(listener, cid, dec);
						send_to_ctr(updater, TYPE_EVENT, ACTION_NOOP, out); 
					}
					else {
						char dec[] = "DENY";
						send_to_client(listener, cid, dec);
						send_to_ctr(updater, TYPE_EVENT, ACTION_NOOP, out); 
					}
					
				}

				free(meta);
				free(out); /* zmq might free this automatically, causing double free */
			}
		
		}

	}


}

