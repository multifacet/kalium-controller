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

khash_t(state_table)* ptr_state_table = kh_init(state_table);
khash_t(io_whitelist)* ptr_io_whitelist = kh_init(io_whitelist);
khash_t(ip_whitelist)* ptr_ip_whitelist = kh_init(ip_whitelist);
khash_t(url_whitelist)* ptr_url_whitelist = kh_init(url_whitelist);
khash_t(policy_table)* ptr_policy_table = kh_init(policy_table);
khash_t(event_mapping_table)* ptr_event_mapping_table = kh_init(event_mapping_table);

//ecc keys for self and previous nodes
static keys_t self_key;
static keys_t prev_key[10];

static int prev_cnt = 0;

static int ior = 0;
static int netr = 0;

static list_node* ptr_curr_state;
static list_node* ptr_list_head;

const struct uECC_Curve_t* curve = uECC_secp256r1();

char* get_func_name(){
#ifdef DEBUG
	char* out = "test0";
	return out;
#else
	return getenv("AWS_LAMBDA_FUNCTION_NAME");
#endif
}

char* get_region_name(){
#ifdef DEBUG
	char* out = "AWS_EAST";
	return out;
#else
	return getenv("AWS_REGION");
#endif
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


char* rand_string(char *str, size_t size)
{
	srand ( time(NULL) );
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK1234567890";
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}



void strip(char* str, char c) {
    char *pr = str, *pw = str;
    while (*pr) {
        *pw = *pr++;
        pw += (*pw != c);
    }
    *pw = '\0';
}


bool starts_with(char *str, char *pre)
{
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}



void get_inst_id(char* inst_id){

	FILE * fp;
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
        char* ids[3];
        const char* sep = "/";
        split_str(line, sep, ids);
        strncpy(inst_id, ids[2], 14);
        inst_id[14] = '\0';
    }

    fclose(fp);


}

long int get_time(void) {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    //return (((long int)tv.tv_sec)*1000)+(tv.tv_usec/1000);
    return (long int)1000000 * tv.tv_sec + tv.tv_usec;
}

int get_event_id(unsigned long event_hash)
{
	khiter_t idx;
	int eid = 0;
	idx = kh_get(event_mapping_table, ptr_event_mapping_table, event_hash);
	eid = kh_value(ptr_event_mapping_table, idx);
	return eid;
}

unsigned long djb2hash(char *func_name, char* event, char* url, char* action)
{	
	int _len = strlen(func_name) + strlen(event) + strlen(url) + strlen(action) + 1;
	char* hash_input = (char*)calloc(_len, sizeof(char));
	snprintf(hash_input, _len, "%s%s%s%s", func_name, event, url, action);
    unsigned long hash = 5381;
    int c = 0;

    while (c = *hash_input++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

void my_free (void *data, void *hint)
{
	free (data);
}

char* find_path_name(int wd, struct path_info path_list[]){

    for (int i = 0; i < 1024; i++){
      if (path_list[i].wd == wd){
        return path_list[i].name;
      }
    }

    return NULL;

}

void copy_file(char* src, char* dst) {

      FILE *fptr1, *fptr2;
      fptr1 = fopen(src, "r");
      fptr2 = fopen(dst, "w");
      char c; 
      c = fgetc(fptr1);
      while (c != EOF)
      {
          fputc(c, fptr2);
          c = fgetc(fptr1);
      }
      fclose(fptr1);
      fclose(fptr2);
}


int recursive_add(const char *name, int ifd, int file_cnt, struct path_info path_list[], struct pollfd fds[])
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(name)))
        return file_cnt;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            char* path = (char*) malloc(1024 * sizeof(char));
            memset(path, '\0', 1024);
            snprintf(path, 1024, "%s/%s", name, entry->d_name);
            

            file_cnt += 1;
            int wd = inotify_add_watch(ifd, path, IN_ALL_EVENTS); 
            fds[file_cnt].events = POLLIN;
            fds[file_cnt].fd = ifd;

            path_list[file_cnt].wd = wd;
            path_list[file_cnt].name = path;

            printf("Watching %d, %s, %d\n", wd, find_path_name(wd, path_list), file_cnt);

            file_cnt = recursive_add(path, ifd, file_cnt, path_list, fds);
        } 
    }
    closedir(dir);

    return file_cnt;
}


int lookup(const int h_name, char* key)
{	

	khiter_t k;
	int is_missing;
	switch(h_name)
	{
		case state_table: 
			k =  kh_get(state_table, ptr_state_table, key);
			is_missing = (k == kh_end(ptr_state_table));
			break;

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

void key_init_req(void* socket, char* guard_id)
{


	char* msg_str = msg_init(guard_id);
	zmq_msg_t msg; 

	int rc = zmq_msg_init_data (&msg, msg_str, strlen(msg_str) , my_free, NULL); 

	//printf ("Init guard key\n");
	zmq_msg_send (&msg, socket, 0); 

	zmq_msg_close(&msg);

}



void key_init_handler(char* msg_body, int msg_body_len)
{


	self_key = str_to_keys(msg_body);

	prev_cnt = msg_body_len / 96 - 1;

	for (int i = 0; i < prev_cnt; i++){
		prev_key[i] = str_to_keys(msg_body + (i + 1) * 96);

	}

}



void policy_init_req(void* socket, char* guard_id)
{

	char* msg_str = msg_basic(TYPE_POLICY, ACTION_POLICY_INIT, guard_id, self_key);

	zmq_msg_t msg; 

	int rc = zmq_msg_init_data (&msg, msg_str, strlen(msg_str) , my_free, NULL); 

	//printf ("Init guard policy\n");
	zmq_msg_send (&msg, socket, 0); 

	zmq_msg_close(&msg);
}


void info_init_req(void* socket, char* info)
{

	char* msg_str = msg_basic(TYPE_INFO, TYPE_INFO, info, self_key);

	zmq_msg_t msg; 

	int rc = zmq_msg_init_data (&msg, msg_str, strlen(msg_str) , my_free, NULL); 

	//printf ("Init info req\n");
	zmq_msg_send (&msg, socket, 0); 

	zmq_msg_close(&msg);
}


void policy_init_handler(char* msg_body, int msg_body_len)
{

	khash_t(io_whitelist)* h_io = (khash_t(io_whitelist)*) ptr_io_whitelist;
	khash_t(ip_whitelist)* h_ip = (khash_t(ip_whitelist)*) ptr_ip_whitelist;
	khash_t(url_whitelist)* h_url = (khash_t(url_whitelist)*) ptr_url_whitelist;

	Document doc;
	doc.Parse(msg_body);


	ior =  doc["IOR"].GetInt();
	netr =  doc["NETR"].GetInt();

	Value& fs = doc["IO"];

	for (SizeType i = 0; i < fs.Size(); i++) {

		char* buf = (char*) calloc(fs[i].GetStringLength() + 1, sizeof(char));
		memcpy(buf, fs[i].GetString(), fs[i].GetStringLength()); 

		kh_set(io_whitelist, h_io, buf, 1);

	}


	Value& ips = doc["IP"];

	for (SizeType i = 0; i < ips.Size(); i++) {

		char* buf = (char*) calloc(ips[i].GetStringLength() + 1, sizeof(char));
		memcpy(buf, ips[i].GetString(), ips[i].GetStringLength()); 

		kh_set(ip_whitelist, h_ip, buf, 1);
	}


	Value& urls = doc["URL"];

	for (SizeType i = 0; i < urls.Size(); i++) {

		char* buf = (char*) calloc(urls[i].GetStringLength() + 1, sizeof(char));
		memcpy(buf, urls[i].GetString(), urls[i].GetStringLength()); 

		kh_set(url_whitelist, h_url, buf, 1);

	}

	

	Value& policy = doc["GRAPH"];
	Value& name = policy["NAME"];
	char* func_name = (char*) calloc(name.GetStringLength() + 1, sizeof(char));
	memcpy(func_name, name.GetString(), name.GetStringLength()); 
	

	
	Value& event_ids = policy["EVENTID"];

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
	Value& ns = policy["ns"];
	Value& es = policy["es"];


	for (SizeType i = 0; i < ns.Size(); i++) {
		
		Value& node = ns[i];
		Node* tnode = (Node*) malloc(sizeof(struct node));;
		tnode->id = node["id"].GetInt();
		tnode->next_cnt = 0;
		tnode->loop_cnt = node["cnt"].GetInt();
		list_append(graph, (void*)tnode);
	}

	for (SizeType i = 0; i < es.Size(); i++) {
		Value& dsts = es[i]["1"];
		int src = es[i]["0"].GetInt();
		node* p_ns = (node*)list_get_element(graph, src+1);
		for (SizeType j = 0; j < dsts.Size(); j++) {
			int dst = dsts[j].GetInt();

			if (dst != -1) {
				list* p_nd = (list*)list_get_pointer(graph, dst+1);
				p_ns -> successors[p_ns->next_cnt] = p_nd;
				p_ns -> next_cnt =  p_ns -> next_cnt + 1;
			}
			else {

				p_ns -> successors[p_ns->next_cnt] = graph;
				p_ns -> next_cnt =  p_ns -> next_cnt + 1;
			}
			;
		}

	}

	khash_t(policy_table)* h_policy = (khash_t(policy_table)*) ptr_policy_table;
	kh_set(policy_table, h_policy, func_name, graph);

	ptr_curr_state = graph;
	ptr_list_head = graph;


	

}



void* disk_monitor(void* context)
{

  struct path_info path_list[1024];
  struct pollfd fds[1024];
  int file_cnt = 0;
  int nfds = file_cnt + 1;

  int ifd, wd;
  char buf[INOTIFY_EVENT_BUF_LEN] __attribute__ ((aligned(8)));
  int numRead;
  char *p;
  struct inotify_event *ev;

  char* root_dir = "/tmp";

  ifd = inotify_init();
  wd = inotify_add_watch(ifd, root_dir, IN_ALL_EVENTS);
 
  fds[file_cnt].events = POLLIN;
  fds[file_cnt].fd = ifd;


  path_list[file_cnt].wd = wd;
  path_list[file_cnt].name = (char*) malloc((strlen(root_dir) + 1) * sizeof(char));
  strncpy(path_list[file_cnt].name, root_dir, strlen(root_dir));
  path_list[file_cnt].name[strlen(root_dir)] = '\0';

  printf("Watching %d, %s, %d\n", wd, find_path_name(wd, path_list), file_cnt);
  

  file_cnt = recursive_add("/tmp", ifd, file_cnt, path_list, fds);
  
  nfds = file_cnt + 1;

  


  while(1) {

    int num_events = poll(fds, nfds, -1);

    for (int i = 0; i < num_events; i++) {

      for (int cnt = 0; cnt < nfds; cnt++) {

        if (fds[cnt].revents & POLLIN) {

          numRead = read(fds[cnt].fd, buf, INOTIFY_EVENT_BUF_LEN);

          for (p = buf; p < buf + numRead; ) {

            ev = (struct inotify_event *) p;
            
            if (!(ev -> mask ^ (IN_CREATE | IN_ISDIR)))  {
                
                file_cnt += 1;
                nfds += 1;

                char* parent_path = find_path_name(ev->wd, path_list);
                char* sub_path = ev -> name;
                int new_path_len = strlen(parent_path) + strlen(sub_path);
                char* new_path = (char*) malloc( (new_path_len + 1) * sizeof(char));
                sprintf(new_path, "%s/%s", parent_path, sub_path);
                new_path[new_path_len+1] = '\0';

                int wd = inotify_add_watch(ifd, new_path, IN_ALL_EVENTS); 
                fds[file_cnt].events = POLLIN;
                fds[file_cnt].fd = ifd;

                path_list[file_cnt].wd = wd;
                path_list[file_cnt].name = new_path;
                
                // printf("create new dir %d, %s, %s\n", wd, new_path, ev->name);
            }

            if (!(ev -> mask ^ (IN_CREATE)))  {

                char* parent_path = find_path_name(ev->wd, path_list);
                char* sub_path = ev -> name;
                int file_path_len = strlen(parent_path) + strlen(sub_path);
                char* file_path = (char*) malloc( (file_path_len + 1) * sizeof(char));
                sprintf(file_path, "%s/%s", parent_path, sub_path);
                file_path[file_path_len+1] = '\0';
                // printf("create new file %s\n", file_path);
                // struct stat info;
                // stat(file_path, &info);
                // printf("original permissions were: %08x\n", info.st_mode);
                int ret = lookup(io_whitelist, file_path);
                
                if (ret) {
                  struct stat info;
                  stat(file_path, &info);
                  printf("%s, %d, %d, %d\n", file_path, ret, getuid(), info.st_uid) ;
                  if (getuid() != info.st_uid) {
                  	
                    copy_file(file_path, "tmp.db");
                  

                    int rr = remove(file_path);
  					if (0 == rr) {
                    	copy_file("tmp.db", file_path); 
                    }
                  }
                	if (chmod(file_path, S_IRWXO | S_IRWXG ) != 0)
                      	perror("chmod() error");
                }
            }

            if (!(ev -> mask ^ (IN_MODIFY)))  {

                // printf("modify file %d, %s\n", ev->wd, ev->name);
            }

            p += sizeof(struct inotify_event) + ev->len;
          }

        }
      }
    }

  }

}




void policy_init() {

	list_node* ptr = ptr_list_head->next;
	while (ptr != ptr_list_head) {
		
		node* nptr = (node*) ptr-> data;
		
		nptr->ctr = nptr->loop_cnt;
		log_info("ctr:%d", nptr->ctr);
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
		EXIT_FAILURE;
	}

	
	list_node* ptr = ptr_curr_state;
	if (ptr == ptr_list_head) {
		policy_init();
		ptr_curr_state = ptr_curr_state-> next;
		ptr = ptr_curr_state;
	}
	
	node* nptr = (node*) ptr-> data;

	log_info("%d, %d, %d", nptr->id, nptr->next_cnt, nptr->ctr);

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





int main(int argc, char const *argv[])
{


	void *context = zmq_ctx_new ();
	void *updater = zmq_socket (context, ZMQ_DEALER);
	void *listener = zmq_socket (context, ZMQ_REP);
	void *backend = zmq_socket (context, ZMQ_ROUTER);

	char conn_str[100];
	char identity [128];
	char* guard_id = get_func_name();

	memset(identity, '\0', sizeof(identity));
	sprintf (identity, "%s%ld", guard_id, get_time());
	strip(identity, '-');

	char rid[16];
	memset(rid, '\0', sizeof(rid));
	get_inst_id(rid);


	zmq_setsockopt (updater, ZMQ_IDENTITY, identity, sizeof(identity));
	sprintf(conn_str, "tcp://%s:%d", CTR_IP, CTR_PORT);
  	log_info("connect to ctr: %s", conn_str);
	zmq_connect (updater, conn_str);

	zmq_bind (backend, "inproc://diskmonitor");
	log_info("start disk monitor");

	sprintf(conn_str, "tcp://*:%d", GUARD_PORT);
	zmq_bind (listener, conn_str);
	log_info("wait for function: %s", conn_str);


	zmq_pollitem_t items [] = { 
		{ updater, 0, ZMQ_POLLIN, 0 }, 
		{ listener, 0, ZMQ_POLLIN, 0 }, 
		{ backend, 0, ZMQ_POLLIN, 0 }, 
	};


	key_init_req(updater, guard_id);
	log_info("register to ctr");

	// pthread_t th_disk_monitor;
	// pthread_t th_state;
	// pthread_t th_test;


	while (1) {
		zmq_poll (items, 3, -1);

		if (items [0].revents & ZMQ_POLLIN) {
			
			zmq_msg_t buf;
			int msg_size;

			zmq_msg_init (&buf);

			zmq_msg_recv (&buf, updater, 0);

			msg_size = zmq_msg_size(&buf);

			if (msg_size <= 1) continue;

			msg_t recv_msg = msg_parser((char*) zmq_msg_data (&buf));
			char type = recv_msg.header.type;
			char action = recv_msg.header.action;


			if (TYPE_KEY_DIST == type){
				
				key_init_handler(recv_msg.body, strtol(recv_msg.header.len, NULL, 16));
				policy_init_req(updater, guard_id);


			}
			else if ((TYPE_POLICY == type) && (ACTION_POLICY_ADD == action)){
				
				policy_init_handler(recv_msg.body, strtol(recv_msg.header.len, NULL, 16));
				log_info("finish registration; get policy");
				
			}

			else if ((TYPE_TEST == type)){
				log_info("handle test policy");

				
			}
			else if ((TYPE_CHECK_RESP == type)){
				// printf("get ctr resp %s\n", recv_msg_copy.body);
				
				zmq_msg_t resp; 
				printf("send check resp\n");
				char dec[] = "ALLOW"; /* weird issue: zmq_msg_init_data can't take macros as input */ 
				zmq_msg_init_data (&resp, dec, strlen(dec) , NULL, NULL);
				zmq_msg_send (&resp, listener, 0); 
				zmq_msg_close(&resp);
				
			}


		}
		if (items [1].revents & ZMQ_POLLIN) {
			

			zmq_msg_t buf;
			int msg_size;
    		char* msg_str;
    		zmq_msg_t resp; 

			zmq_msg_init (&buf);
			zmq_msg_recv (&buf, listener, 0);
			msg_size = zmq_msg_size(&buf);

			if (msg_size <= 1) continue;

			char* tmp = (char*) zmq_msg_data (&buf);
			char event[5] = {0};
			strncpy(event, tmp, EVENT_LEN);
			event[5] = '\0';
				
			char* body = tmp + EVENT_LEN + 1;
			body[msg_size - 4 - 1] = '\0';

			
    		Document d;
    		char* meta;
    		char* data;
    		d.Parse(body);

    		if (strncmp(EVENT_CHECK, event, EVENT_LEN) == 0) {
    			
				zmq_msg_init_data (&resp, guard_id, strlen(guard_id) , NULL, NULL);
				zmq_msg_send (&resp, listener, 0); 
				zmq_msg_close(&resp);
				
				msg_str = msg_basic_2(TYPE_CHECK_STATUS, ACTION_TEST, guard_id, self_key);
				zmq_msg_t msg0;
				zmq_msg_init_data (&msg0, msg_str, strlen(msg_str) , NULL, NULL); 
				zmq_msg_send (&msg0, updater, 0); 
				zmq_msg_close(&msg0); 
				continue;	
			}

    		if (!d.IsObject()){
    			log_error("message is not an valid json object!");
    			char error_info[] = "no object";
				zmq_msg_init_data (&resp, error_info, strlen(error_info) , NULL, NULL);
    			
 			}
 			else if (!d.HasMember("meta")){
 				log_error("message does not has the meta field!");
 				char error_info[] = "no meta";
				zmq_msg_init_data (&resp, error_info, strlen(error_info) , NULL, NULL);
 			}	

    		else {

    			
				Value& meta_t = d["meta"];
				Value& data_t = d["data"];

				meta = (char*)calloc(strlen(meta_t.GetString()) + 1, sizeof(char));
				strncpy(meta, meta_t.GetString(), strlen(meta_t.GetString()));

				data = (char*)calloc(strlen(data_t.GetString()) + 1, sizeof(char));
				strncpy(data, data_t.GetString(), strlen(data_t.GetString()));

				char* out = (char*)calloc(strlen(meta) + strlen(guard_id) + strlen(event) + strlen(rid) + 4, sizeof(char));    
				sprintf(out, "%s:%s:%s:%s", guard_id, event, meta, rid);

				/* 
				* 0 --> url; 1 --> method; 2 --> ip; 3 --> port; 
				* 4 --> has_body; 5 --> request id
				*/
				char* info[6];
				split_str(meta, ":", info);

				unsigned ev_hash = 0; 
				ev_hash = djb2hash(guard_id, event, info[0], info[1]);
			
				int ev_id = get_event_id(ev_hash);
	
				printf("%u, %d\n", ev_hash, ev_id);

				if (strncmp(EVENT_GET, event, EVENT_LEN) == 0){
					
					check_policy(ev_id);

					msg_str = msg_basic_2(TYPE_CHECK_EVENT, ACTION_TEST, out, self_key);
					zmq_msg_t msg0;
					
					zmq_msg_init_data(&msg0, msg_str, strlen(msg_str) , NULL, NULL); 
					
					zmq_msg_send(&msg0, updater, 0); 

					zmq_msg_close(&msg0); 

					free(meta);

					free(data);
					
					continue;
					
					

				}

				else if (strncmp(EVENT_END, event, EVENT_LEN) == 0){
					printf("event end\n");
					policy_init();
				}

				else if ((strncmp(EVENT_SEND, event, EVENT_LEN) == 0) || 
					(strncmp(EVENT_RESP, event, EVENT_LEN) == 0)){
					printf("event send/resp\n");
					//write_log(fout, string("get send event"));

					
					

				   	msg_str = msg_basic_2(TYPE_EVENT, ACTION_TEST, out, self_key);
					

					//write_log(fout, string("send to ctr"));
					/*
						if domain/ip is allowed:
							if domain in guard-enabled:
								return tag
							else:
								return 1
						else:
							return 0
					*/

					// if (check_policy(info[0], info[1], info[2])) {
					if (check_policy(ev_id)) {
						
						char dec[] = "ALLOW"; 
						zmq_msg_init_data(&resp, dec, strlen(dec), NULL, NULL); 
							// if (strstr(info[0], "google") != NULL) {
							// 	char* t = "ALLOW";
							// 	zmq_msg_init_data (&resp, t, strlen(t) , NULL, NULL); 
	
							// }
							// else if (starts_with (info[0], "lambda.")){

							// 	zmq_msg_init_data (&resp, guard_id, strlen(guard_id) , NULL, NULL); 

							// }
							// else {
							// 	zmq_msg_init_data (&resp, guard_id, strlen(guard_id) , NULL, NULL); 
							// }
					}
					else{
						log_info("2");
						if (!data_t.IsObject()) {
							char dec[] = "DENY";
							// printf("ask for body\n");
							zmq_msg_init_data(&resp, dec, strlen(dec) , NULL, NULL); 
						}
						else if (info[4] != 0) {
							//printf("get all\n");
							// char* t = "MORE";
							char dec[] = "DENY";
							zmq_msg_init_data(&resp, dec, strlen(dec) , NULL, NULL); 
						}
						else {
							printf("!!!!!!!!\n");
			
						}
					}

					
				}

				
				


			}
			zmq_msg_send (&resp, listener, 0); 
			zmq_msg_close(&resp);

			zmq_msg_t msg0;
			zmq_msg_init_data (&msg0, msg_str, strlen(msg_str) , NULL, NULL); 
			zmq_msg_send (&msg0, updater, 0); 
			zmq_msg_close(&msg0); 

		}

		if (items [2].revents & ZMQ_POLLIN) {

			zmq_msg_t buf;
			int msg_size;

			zmq_msg_init (&buf);

			zmq_msg_recv (&buf, backend, 0);

			msg_size = zmq_msg_size(&buf);

			if (msg_size <= 1) continue;

			printf("get message %d, %s\n", msg_size, (char*) zmq_msg_data (&buf));
		}

	}


}

