#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include <stdbool.h>
#include "thread.h"
#include "interrupt.h"

enum{
	UNUSED = 0,
	RUNNING = 1,
	BLOCKED = 2,
	KILLED = 3,
	BLOCKED_AND_KILLED = 4
};

/* This is the thread control block */
struct thread{
	Tid id;
	bool recovered;
	void* stack; //pointer to thread stack
	struct wait_queue* wq;
	ucontext_t context; //context of current thread
};

typedef struct Thread_Node{
	struct thread* thread_data;
	struct Thread_Node* next;
}thread_node;

typedef struct Thread_Queue{
	thread_node* head;
	thread_node* tail;
}thread_queue;

/* This is the wait queue structure */
struct wait_queue {
	thread_queue* waitlist;
};

typedef struct Free_Thread_ID{
	Tid id;
	struct Free_Thread_ID* next;
}free_id;

typedef struct Free_Thread_ID_List{
	free_id* head;
	free_id* tail;
}free_thread_id_list;

//global variables
int thread_status[THREAD_MAX_THREADS];
struct thread* thread_array[THREAD_MAX_THREADS];

thread_queue* ready_queue; //queue storing ready threads
thread_queue* killed_queue; //queue storing killed threads
thread_queue* destroy_queue; //queue storing threads that have exited and can be destroyed
free_thread_id_list* free_id_list; //list storing unoccupied thread identifiers
struct thread* running_thread; //thread that is currently running

//add new thread to queue
void append_queue(struct thread* new_thread, thread_queue* queue){
	int prev_enabled = interrupts_off();
	thread_node* new_node = (thread_node*)malloc(sizeof(thread_node));
	new_node->thread_data = new_thread;
	new_node->next = NULL;
	if(queue->head == NULL)
		queue->head = queue->tail = new_node;
	else{
		queue->tail->next = new_node;
		queue->tail = queue->tail->next;
	}
	interrupts_set(prev_enabled);
}

//extract first thread from thread queue
struct thread* pop_queue(thread_queue* queue){
	int prev_enabled = interrupts_off();
	//if(queue == ready_queue)
	//else if(queue == killed_queue)
	//else if(queue == destroy_queue)
	struct thread* target = queue->head->thread_data;
	if(queue->head == queue->tail){
		free(queue->head);
		queue->head = NULL;
		queue->tail = NULL;
		
		assert((queue->head != NULL && queue->tail != NULL) || (queue->head == NULL && queue->tail == NULL));
		interrupts_set(prev_enabled);
		return target;
	}
	thread_node* newHead = queue->head->next;
	free(queue->head);
	queue->head = newHead;
	assert((queue->head != NULL && queue->tail != NULL) || (queue->head == NULL && queue->tail == NULL));
	interrupts_set(prev_enabled);
	return target;
}

//searches the ready queue for the thread to activate
struct thread* extract_queue(Tid want_tid, thread_queue* queue){
	int prev_enabled = interrupts_off();
	struct thread* target = NULL;
	if(queue->head->thread_data->id == want_tid){
		target = queue->head->thread_data;
		if(queue->head == queue->tail){
			free(queue->head);
			queue->head = NULL;
			queue->tail = NULL;
			interrupts_set(prev_enabled);
			return target;
		}
		thread_node* newHead = queue->head->next;
		free(queue->head);
		queue->head = newHead;
		interrupts_set(prev_enabled);
		return target;
	}
	thread_node* prev = queue->head;
	do{
		if(prev->next->thread_data->id == want_tid){
			target = prev->next->thread_data;
			if(prev->next == queue->tail){
				free(queue->tail);
				queue->tail = prev;
				queue->tail->next = NULL;
			}
			else{
				thread_node* newNext = prev->next->next;
				free(prev->next);
				prev->next = newNext;
			}
			interrupts_set(prev_enabled);
			return target;
		}
		prev = prev->next;
	}while(prev->next != NULL);
	interrupts_set(prev_enabled);
	return target;
}

void clear_thread_queue(thread_queue* queue){
	int prev_enabled = interrupts_off();
	thread_node* tbd;
	while(queue->head != NULL){
		tbd = queue->head->next;
		free(queue->head->thread_data->stack);
		free(queue->head->thread_data->wq->waitlist);
		free(queue->head->thread_data->wq);
		free(queue->head->thread_data);
		free(queue->head);
		queue->head = tbd;
	}
	queue->tail = queue->head;
	interrupts_set(prev_enabled);
}

//add a new unused thread identifier to free_id_list
void add_free_id(Tid avail_id){
	int prev_enabled = interrupts_off();
	free_id* new_free_id = (free_id*)malloc(sizeof(free_id));
	new_free_id->id = avail_id;
	new_free_id->next = NULL;
	if(free_id_list->head == NULL)
		free_id_list->head = free_id_list->tail = new_free_id;
	else
		free_id_list->tail = free_id_list->tail->next = new_free_id;
	interrupts_set(prev_enabled);
}

//extract first unused thread identifier from free_id_list
Tid assign_id(){
	int prev_enabled = interrupts_off();
	Tid ret = free_id_list->head->id;
	if(free_id_list->head == free_id_list->tail){
		free(free_id_list->head);
		free_id_list->head = free_id_list->tail = NULL;
		interrupts_set(prev_enabled);
		return ret;
	}
	free_id* newHead = free_id_list->head->next;
	free(free_id_list->head);
	free_id_list->head = newHead;
	interrupts_set(prev_enabled);
	return ret;
}

void remove_all_id(){
	int prev_enabled = interrupts_off();
	free_id* tbd;
	while(free_id_list->head != NULL){
		tbd = free_id_list->head->next;
		free(free_id_list->head);
		free_id_list->head = tbd;
	}
	interrupts_set(prev_enabled);
}

/*Lab 2 functions*/
void thread_init(void){
	ready_queue = (thread_queue*)malloc(sizeof(thread_queue));
	killed_queue = (thread_queue*)malloc(sizeof(thread_queue));
	destroy_queue = (thread_queue*)malloc(sizeof(thread_queue));
	ready_queue->head = ready_queue->tail = killed_queue->head = killed_queue->tail = destroy_queue->head = destroy_queue->tail = NULL;
	free_id_list = (free_thread_id_list*)malloc(sizeof(free_thread_id_list));
	free_id_list->head = free_id_list->tail = NULL;
	for(Tid i = 1; i < THREAD_MAX_THREADS; i++){
		thread_status[i] = UNUSED; //initialize to unused;
		add_free_id(i);
	}
	struct thread* kernel_thread = (struct thread*)malloc(sizeof(struct thread));
	kernel_thread->id = 0;
	kernel_thread->recovered = false;
	thread_status[0] = RUNNING;
	kernel_thread->wq = wait_queue_create();
	running_thread = kernel_thread;
	thread_array[0] = running_thread;
}

Tid thread_id(){
	return running_thread->id;
}

void thread_stub(void (*thread_main)(void *), void* arg){
	interrupts_on(); //enable interrupt, in case there was a previously running thread that yielded to this, in which case interrupts are disabled
	thread_main(arg);
	thread_exit();
	//only get here if ready_queue and killed_queue are both empty, as otherwise another thread from ready queue would run
	interrupts_off();
	clear_thread_queue(destroy_queue); //destroy any remaining exited threads
	clear_thread_queue(killed_queue); //destroy any remaining killed threads
	remove_all_id();
	free(ready_queue);
	free(killed_queue);
	free(destroy_queue);
	free(free_id_list);
	exit(0);
}

Tid thread_create(void (*fn)(void *), void *parg){
	int prev_enabled = interrupts_off();
	struct thread* new_thread = (struct thread*)malloc(sizeof(struct thread));
	if(new_thread == NULL){
		interrupts_set(prev_enabled);
		return THREAD_NOMEMORY;
	}
	if(free_id_list->head == NULL){
		interrupts_set(prev_enabled);
		return THREAD_NOMORE;
	}
	new_thread->id = assign_id(); //get an unused thread identifier for the new thread
	thread_array[new_thread->id] = new_thread;
	thread_status[new_thread->id] = RUNNING; //set status of the newly created thread's identifier to 1 (in-use)
	new_thread->recovered = false;
	getcontext(&(new_thread->context));
	(new_thread->context).uc_mcontext.gregs[REG_RIP] = (long long int)(&thread_stub); //reset instruction pointer to thread stub function
	(new_thread->context).uc_mcontext.gregs[REG_RDI] = (long long int)fn; //pass first argument into rdi register
	(new_thread->context).uc_mcontext.gregs[REG_RSI] = (long long int)parg; //pass second argument into rsi register
	void* thread_stack = malloc(THREAD_MIN_STACK); //allocate new stack for thread
	if(thread_stack == NULL){
		free(new_thread);
		interrupts_set(prev_enabled);
		return THREAD_NOMEMORY;
	}
	new_thread->stack = thread_stack;
	(new_thread->context).uc_mcontext.gregs[REG_RSP] = (long long int)(new_thread->stack) + THREAD_MIN_STACK - 8; //set stack pointer to top of stack
	new_thread->wq = wait_queue_create(); //crete thread's wait queue
	append_queue(new_thread, ready_queue); //add thread to ready queue
	interrupts_set(prev_enabled); //restore interrupts
	return new_thread->id;
}

Tid thread_yield(Tid want_tid){
	int prev_enabled = interrupts_off(); //disable interrupts
	Tid yield_id;
	bool no_ready = ready_queue->head == NULL;
	if(want_tid < THREAD_SELF || want_tid >= THREAD_MAX_THREADS || (want_tid >= 0 && thread_status[want_tid] != RUNNING && thread_status[want_tid] != KILLED)){
		interrupts_set(prev_enabled);
		return THREAD_INVALID;
	}
	if(want_tid == THREAD_SELF || want_tid == running_thread->id){ //yield to self
		interrupts_set(prev_enabled);
		return running_thread->id;
	}
	if(no_ready && killed_queue->head == NULL){ //no thread, ready or killed, to yield to
		interrupts_set(prev_enabled);
		return THREAD_NONE;
	}
	append_queue(running_thread, ready_queue);
	getcontext(&(ready_queue->tail->thread_data->context)); //save current thread context for ready thread, instruction pointer points to if statement
	if(!(running_thread->recovered)){
		running_thread->recovered = true;
		if(want_tid >= 0 && thread_status[want_tid] == KILLED){
			running_thread = extract_queue(want_tid, killed_queue);
			thread_exit();
		}
		else{
			if(want_tid == THREAD_ANY){
				if(!no_ready)
					running_thread = pop_queue(ready_queue);
				else{
					running_thread = pop_queue(killed_queue);
					thread_exit();
				}
			}
			else running_thread = extract_queue(want_tid, ready_queue);
			yield_id = running_thread->id;
			setcontext(&(running_thread->context));
		}
	}
	running_thread->recovered = false; //reset recovered flag
	clear_thread_queue(destroy_queue); //destroy all remaining exited threads
	interrupts_set(prev_enabled);
	return yield_id;
}

void thread_exit(){
	interrupts_off();
	//printf("in thread exit...\n");
	thread_wakeup(running_thread->wq, 1);
	thread_status[running_thread->id] = UNUSED;
	add_free_id(running_thread->id);
	thread_array[running_thread->id] = NULL;
	append_queue(running_thread, destroy_queue);
	struct thread* tbd;
	while(ready_queue->head == NULL && killed_queue->head != NULL){
		tbd = pop_queue(killed_queue);
		thread_wakeup(tbd->wq, 1);
		thread_status[tbd->id] = UNUSED;
		add_free_id(tbd->id);
		thread_array[tbd->id] = NULL;
	}
	if(ready_queue->head != NULL){
		running_thread = pop_queue(ready_queue);
		setcontext(&(running_thread->context));
	}
	extract_queue(running_thread->id, destroy_queue);
}

Tid thread_kill(Tid tid){
	int prev_enabled = interrupts_off();
	if(tid < 0 || tid >= THREAD_MAX_THREADS || tid == running_thread->id || (thread_status[tid] != RUNNING && thread_status[tid] != BLOCKED)){
		interrupts_set(prev_enabled);
		return THREAD_INVALID;
	}
	if(thread_status[tid] == BLOCKED){
		thread_status[tid] = BLOCKED_AND_KILLED;
		interrupts_set(prev_enabled);
		return tid;
	}
	thread_status[tid] = KILLED; //kill status
	append_queue(extract_queue(tid, ready_queue), killed_queue);
	interrupts_set(prev_enabled); //restore interrupts
	return killed_queue->tail->thread_data->id;
}

/*******************************************************************
 * Important: The rest of the code should be implemented in Lab 3. *
 *******************************************************************/

/* make sure to fill the wait_queue structure defined above */
struct wait_queue* wait_queue_create(){
	int prev_enabled = interrupts_off();
	struct wait_queue* wq = (struct wait_queue*)malloc(sizeof(struct wait_queue));
	assert(wq);
	wq->waitlist = (thread_queue*)malloc(sizeof(thread_queue));
	wq->waitlist->head = wq->waitlist->tail = NULL;
	interrupts_set(prev_enabled);
	return wq;
}

void wait_queue_destroy(struct wait_queue *wq){
	int prev_enabled = interrupts_off();
	free(wq->waitlist);
	free(wq);
	interrupts_set(prev_enabled);
}

Tid thread_sleep(struct wait_queue *queue){
	int prev_enabled = interrupts_off();
	if(queue == NULL){
		interrupts_set(prev_enabled);
		return THREAD_INVALID;
	}
	if(ready_queue->head == NULL){
		interrupts_set(prev_enabled);
		return THREAD_NONE;
	}
	Tid next_to_run;
	append_queue(running_thread, queue->waitlist); //add current thread to wait queue
	thread_status[running_thread->id] = BLOCKED; //set current thread status to blocked
	getcontext(&(queue->waitlist->tail->thread_data->context));
	if(!(running_thread->recovered)){
		running_thread->recovered = true;
		running_thread = pop_queue(ready_queue);
		next_to_run = running_thread->id;
		setcontext(&(running_thread->context));
	}
	running_thread->recovered = false;
	clear_thread_queue(destroy_queue);
	interrupts_set(prev_enabled);
	return next_to_run;
}

/* when the 'all' parameter is 1, wakeup all threads waiting in the queue.
 * returns whether a thread was woken up on not. */
int thread_wakeup(struct wait_queue *queue, int all){
	int prev_enabled = interrupts_off();
	if(queue == NULL){
		interrupts_set(prev_enabled);
		return 0;
	}
	if(queue->waitlist->head == NULL){
		interrupts_set(prev_enabled);
		return 0;
	}
	struct thread* wakeup;
	if(all){
		thread_node* tbd;
		int wakeup_num = 0;
		do{
			tbd = queue->waitlist->head->next;
			wakeup = queue->waitlist->head->thread_data;
			if(thread_status[wakeup->id] == BLOCKED_AND_KILLED){
				append_queue(wakeup, killed_queue);
				thread_status[wakeup->id] = KILLED;
			}
			else{
				append_queue(wakeup, ready_queue);
				thread_status[wakeup->id] = RUNNING;
			}
			wakeup_num++;
			free(queue->waitlist->head);
			queue->waitlist->head = tbd;
		}while(queue->waitlist->head != NULL);
		interrupts_set(prev_enabled);
		return wakeup_num;
	}
	thread_node* newHead = queue->waitlist->head->next;
	wakeup = queue->waitlist->head->thread_data;
	if(thread_status[wakeup->id] == BLOCKED_AND_KILLED){
		append_queue(wakeup, killed_queue);
		thread_status[wakeup->id] = KILLED;
	}
	else{
		append_queue(wakeup, ready_queue);
		thread_status[wakeup->id] = RUNNING;
	}
	free(queue->waitlist->head);
	queue->waitlist->head = newHead;
	interrupts_set(prev_enabled);
	return 1;
}

/* suspend current thread until Thread tid exits */
Tid thread_wait(Tid tid){
	int prev_enabled = interrupts_off();
	if(tid < 0 || tid >= THREAD_MAX_THREADS || tid == running_thread->id || thread_status[tid] == UNUSED){
		interrupts_set(prev_enabled);
		return THREAD_INVALID;
	}
	Tid wait_for = (thread_array[tid])->id;
	thread_sleep((thread_array[tid])->wq);
	interrupts_set(prev_enabled);
	return wait_for;
}

struct lock {
	Tid owner_id;
	struct wait_queue* wq;
};

struct lock* lock_create(){
	struct lock* mutex_lock = malloc(sizeof(struct lock));
	assert(mutex_lock);
	mutex_lock->owner_id = -1;
	mutex_lock->wq = wait_queue_create();
	return mutex_lock;
}

void lock_destroy(struct lock* lock){
	assert(lock != NULL);
	assert(lock->wq->waitlist->head == NULL);
	free(lock->wq->waitlist);
	free(lock->wq);
	free(lock);
}

void lock_acquire(struct lock* lock){
	assert(lock != NULL);
	int prev_enabled = interrupts_off();
	if(lock->owner_id != running_thread->id){//if thread already has acquired lock, do nothing
		while(lock->owner_id != -1){
			thread_sleep(lock->wq);
		}
		lock->owner_id = running_thread->id; //set owner of the lock to currently running thread
	}
	interrupts_set(prev_enabled);
}

void lock_release(struct lock* lock){
	assert(lock != NULL);
	int prev_enabled = interrupts_off();
	if(lock->owner_id == running_thread->id){ //only the thread holding the lock can release it
		thread_wakeup(lock->wq, 1);
		lock->owner_id = -1;
	}
	interrupts_set(prev_enabled);
}

struct cv {
	struct wait_queue* wq;
};

struct cv* cv_create(){
	int prev_enabled = interrupts_off();
	struct cv* cond_var;
	cond_var = malloc(sizeof(struct cv));
	assert(cond_var);
	cond_var->wq = wait_queue_create();
	interrupts_set(prev_enabled);
	return cond_var;
}

void cv_destroy(struct cv* cv){
	assert(cv != NULL);
	int prev_enabled = interrupts_off();
	if(cv->wq->waitlist->head == NULL){
		free(cv->wq->waitlist);
		free(cv->wq);
		free(cv);
	}
	interrupts_set(prev_enabled);
}

void cv_wait(struct cv* cv, struct lock* lock){
	assert(cv != NULL && lock != NULL);
	int prev_enabled = interrupts_off();
	if(lock->owner_id == running_thread->id){ //if lock is not owned by current thread, do nothing
		lock_release(lock);
		thread_sleep(cv->wq);
		lock_acquire(lock);
	}
	interrupts_set(prev_enabled);
}

void cv_signal(struct cv* cv, struct lock* lock){
	assert(cv != NULL && lock != NULL);
	int prev_enabled = interrupts_off();
	if(lock->owner_id == running_thread->id){
		if(cv->wq->waitlist->head != NULL)
			thread_wakeup(cv->wq, 0);
	}
	interrupts_set(prev_enabled);
}

void cv_broadcast(struct cv* cv, struct lock* lock){
	assert(cv != NULL && lock != NULL);
	int prev_enabled = interrupts_off();
	if(lock->owner_id == running_thread->id){
		if(cv->wq->waitlist->head != NULL)
			thread_wakeup(cv->wq, 1);
	}
	interrupts_set(prev_enabled);
}