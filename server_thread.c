#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include "request.h"
#include "server_thread.h"
#include "common.h"

#define ENTRY_NUM 10000

struct server{
	int nr_threads;
	int max_requests;
	int max_cache_size;
	bool exiting;
	pthread_t* worker_array;
	pthread_mutex_t lock;
	pthread_cond_t not_empty;
	pthread_cond_t not_full;
	int* request_buffer;
	int in;
	int out;
};

typedef struct cacheNode{
	struct file_data* data;
	int hashkey;
	int sending;
	struct cacheNode* prev;
	struct cacheNode* next;
}cache_node;

typedef struct cacheStack{
	cache_node* head;
	cache_node* tail;
}cache_stack;

typedef struct evictNode{
	cache_node* node;
	struct evictNode* next;
}evict_node;

typedef struct cacheEntry{
	struct file_data* data;
	cache_node* evict_stack_node; //address of the file in evict stack
	struct cacheEntry* prev;
	struct cacheEntry* next;
}cache_entry;

typedef struct cacheEntries{
	cache_entry* head;
}cache_entries;

typedef struct serverCache{
	cache_entries* table; //cache hashtable
	int max_size;
	int used_size;
	int hashtable_size;
	pthread_mutex_t lock;
}server_cache;

server_cache* cache;
cache_stack* LRU_stack;

static struct file_data* file_data_init(void){
	struct file_data* data = Malloc(sizeof(struct file_data));
	data->file_name = data->file_buf = NULL;
	data->file_size = 0;
	return data;
}

static void file_data_free(struct file_data *data){
	if(data){
		if(data->file_name) free(data->file_name);
		if(data->file_buf) free(data->file_buf);
		free(data);
	}
}

bool cache_evict(int file_size, struct server* sv){
	cache_node* node = LRU_stack->tail;
	evict_node *evict_head = NULL, *newHead;
	cache_entry *entry;
	while(node && file_size > 0){
		if(node->sending == 0){
			newHead = (evict_node*)Malloc(sizeof(evict_node));
			newHead->node = node; 
			newHead->next = evict_head;
			evict_head = newHead;
			file_size -= node->data->file_size;
		}
		node = node->prev;
	}
	if(file_size <= 0){
		while(evict_head){
			node = evict_head->node;
			if(node == LRU_stack->tail){
				if(LRU_stack->head == LRU_stack->tail)
					LRU_stack->head = LRU_stack->tail = NULL;
				else{
					LRU_stack->tail = node->prev;
					LRU_stack->tail->next = NULL;
				}
			}
			else if(node == LRU_stack->head){
				LRU_stack->head = node->next;
				LRU_stack->head->prev = NULL;
			}
			else{
				node->prev->next = node->next;
				node->next->prev = node->prev;
			}
			entry = cache->table[node->hashkey].head;
			while(strcmp(node->data->file_name, entry->data->file_name) != 0)
				entry = entry->next;
			if(entry == cache->table[node->hashkey].head){
				if(!entry->next)
					cache->table[node->hashkey].head = NULL;
				else{
					cache->table[node->hashkey].head = entry->next;
					entry->next->prev = NULL;
				}
			}
			else{
				entry->prev->next = entry->next;
				if(entry->next)
					entry->next->prev = entry->prev;
			}
			cache->used_size -= entry->data->file_size;
			file_data_free(entry->data);
			free(entry);
			free(node);
			newHead = evict_head->next;
			free(evict_head);
			evict_head = newHead;
		}
		return true;
	}
	while(evict_head){
		newHead = evict_head->next;
		free(evict_head);
		evict_head = newHead;
	}
	return false;
}

cache_entry* cache_insert(struct file_data* data, int* key, struct server* sv){
	if(data->file_size > cache->max_size - cache->used_size)
		if(!cache_evict(data->file_size, sv)) return NULL; //not enough cache can be evicted
	cache_entry* newly_cached = (cache_entry*)Malloc(sizeof(cache_entry));
	newly_cached->data = data;
	newly_cached->prev = NULL;
	newly_cached->next = cache->table[*key].head;
	if(newly_cached->next)	
		newly_cached->next->prev = newly_cached;
	cache->table[*key].head = newly_cached;
	cache_node* new_node = (cache_node*)Malloc(sizeof(cache_node));
	new_node->data = data;
	new_node->hashkey = *key;
	new_node->sending = 0;
	new_node->prev = NULL;
	new_node->next = LRU_stack->head;
	if(LRU_stack->head){
		LRU_stack->head->prev = new_node;
		LRU_stack->head = new_node;
	}
	else LRU_stack->head = LRU_stack->tail = new_node;
	newly_cached->evict_stack_node = new_node;
	cache->used_size += data->file_size;
	return newly_cached;
}

cache_entry* cache_lookup(char* name, int* key){
	unsigned long hash = 5381;
	for(int i = 0; name[i] != '\0'; i++)
		hash = (hash << 5) + hash + name[i];
	*key = hash % cache->hashtable_size;
	cache_entry* wanted = cache->table[*key].head;
	while(wanted){
		if(strcmp(wanted->data->file_name, name) == 0){
			if(wanted->evict_stack_node != LRU_stack->head){
				wanted->evict_stack_node->prev->next = wanted->evict_stack_node->next;
				if(wanted->evict_stack_node->next)
					wanted->evict_stack_node->next->prev = wanted->evict_stack_node->prev;
				else LRU_stack->tail = wanted->evict_stack_node->prev;
				wanted->evict_stack_node->prev = NULL;
				wanted->evict_stack_node->next = LRU_stack->head;
				LRU_stack->head->prev = wanted->evict_stack_node;
				LRU_stack->head = wanted->evict_stack_node;
			}
			return wanted;
		}
		wanted = wanted->next;
	}
	return NULL;
}

static void do_server_request(struct server* sv, int connfd){
	struct file_data* data = file_data_init();
	struct request* rq = request_init(connfd, data); //fill data->file_name with name of requested file
	if(!rq){
		file_data_free(data);
		return;
	}
	if(cache->max_size > 0){
		int key;
		pthread_mutex_lock(&(cache->lock));
		cache_entry* wanted = cache_lookup(data->file_name, &key);
		if(!wanted){
			pthread_mutex_unlock(&(cache->lock));
			request_readfile(rq);
			if(data->file_size > cache->max_size){
				request_sendfile(rq);
				request_destroy(rq);
				file_data_free(data);
				return;
			}
			pthread_mutex_lock(&(cache->lock));
			wanted = cache_lookup(data->file_name, &key);
			if(!wanted){
				wanted = cache_insert(data, &key, sv);
				if(!wanted){ //not enough cache space can be evicted
					request_sendfile(rq);
					request_destroy(rq);
					file_data_free(data);
					pthread_mutex_unlock(&(cache->lock));
					return;
				}
			}
		}
		else{
			file_data_free(data);
	 		request_set_data(rq, wanted->data);
		}
		wanted->evict_stack_node->sending++;
		pthread_mutex_unlock(&(cache->lock));
		request_sendfile(rq);
		pthread_mutex_lock(&(cache->lock));
		wanted->evict_stack_node->sending--;
		pthread_mutex_unlock(&(cache->lock));
	}
	else{
		int ret = request_readfile(rq);
		if(ret != 0) // file read failed
			request_sendfile(rq);
		file_data_free(data);
	}
	request_destroy(rq);
}

void worker_process(void* target_server){
	struct server* sv = (struct server*)target_server;
	while(!sv->exiting){
		pthread_mutex_lock(&(sv->lock));
		while(sv->out == sv->in){
			pthread_cond_wait(&(sv->not_empty), &(sv->lock));
			if(sv->exiting){
				pthread_mutex_unlock(&(sv->lock));
				return;
			}
		}
		int connfd = (sv->request_buffer)[sv->out];
		sv->out = (sv->out+1) % (sv->max_requests+1);
		pthread_cond_signal(&(sv->not_full));
		pthread_mutex_unlock(&(sv->lock));
		do_server_request(sv, connfd);
	}
}

struct server* server_init(int nr_threads, int max_requests, int max_cache_size){
	struct server* sv = (struct server*)Malloc(sizeof(struct server));
	sv->nr_threads = nr_threads;
	sv->max_requests = max_requests;
	sv->max_cache_size = 0;
	sv->exiting = false;
	sv->out = sv->in = 0;
	pthread_mutex_init(&(sv->lock), NULL);
	pthread_cond_init(&(sv->not_empty), NULL);
	pthread_cond_init(&(sv->not_full), NULL);
	cache = (server_cache*)Malloc(sizeof(server_cache));
	cache->max_size = 0;
	if (nr_threads > 0 || max_requests > 0 || max_cache_size > 0){
		if(max_cache_size > 0){
			cache->hashtable_size = ENTRY_NUM;
			cache->max_size = max_cache_size;
			cache->used_size = 0;
			cache_entries* cache_table = (cache_entries*)Malloc(cache->hashtable_size*sizeof(cache_entries));
			for(int i = 0; i < cache->hashtable_size; i++)
				cache_table[i].head = NULL;
			cache->table = cache_table;
			pthread_mutex_init(&(cache->lock), NULL);
			LRU_stack = (cache_stack*)Malloc(sizeof(cache_stack));
			LRU_stack->head = LRU_stack->tail = NULL;
		}
		if(nr_threads > 0){
			sv->worker_array = (pthread_t*)Malloc(nr_threads*sizeof(pthread_t));
			for(int i = 0; i < nr_threads; i++)
				pthread_create(&(sv->worker_array[i]), NULL, (void*)worker_process, (void*)sv);
		}
		if(max_requests > 0)
			sv->request_buffer = (int*)Malloc((max_requests+1)*sizeof(int));
	}
	return sv;
}

void server_request(struct server* sv, int connfd){
	if(sv->nr_threads == 0) //no worker threads
		do_server_request(sv, connfd);
	else{
		pthread_mutex_lock(&(sv->lock));
		while((sv->in - sv->out + sv->max_requests+1) % (sv->max_requests+1) == sv->max_requests)
			pthread_cond_wait(&(sv->not_full), &(sv->lock));
		sv->request_buffer[sv->in] = connfd;
		sv->in = (sv->in+1) % (sv->max_requests+1);
		pthread_cond_signal(&(sv->not_empty));
		pthread_mutex_unlock(&(sv->lock));
	}
}

void server_exit(struct server* sv){
	sv->exiting = true;
	pthread_cond_broadcast(&(sv->not_empty));
	for(int i = 0; i < sv->nr_threads; i++)
		pthread_join(sv->worker_array[i], NULL);
	if(cache->max_size > 0){
		cache_entry *del, *tbd;
		for(int i = 0; i < cache->hashtable_size; i++){
			del = cache->table[i].head;
			while(del){
				tbd = del->next;
				file_data_free(del->data);
				free(del->evict_stack_node);
				free(del);
				del = tbd;
			}
		}
		free(LRU_stack);
	}
	free(cache);
	free(sv->worker_array);
	free(sv->request_buffer);
	free(sv);
}