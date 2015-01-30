#ifndef __kdump_types_h__
#define __kdump_types_h__

typedef unsigned long long offset;
#define NULL_offset 0LL

struct kdump_type;

struct kdump_type {
	const char *name;
	int size;
	int offset;
	struct type *origtype;
	struct kdump_type *mastertype;
	struct kdump_type *mtype;
	struct kdump_type *next;
};


struct {
	struct kdump_type base;
	
	offset prev;
	offset next;
} kt_list_head;

struct {
	struct kdump_type base;
	
	offset first;
} kt_hlist_head;

struct {
	struct kdump_type base;
	
	offset next;
} kt_hlist_node;


struct {
	struct kdump_type base;
} kt_int;

struct {
	struct kdump_type base;
} kt_voidp;

struct {
	struct kdump_type base;
	offset nr;
	offset pid_chain;
} kt_upid;

struct {
	struct kdump_type base;
	offset pid;
	offset pids;
	offset stack;
	offset tasks;
	offset thread;
	offset state;
	offset comm;
} kt_task_struct;

struct {
	struct kdump_type base;
	offset sp;
} kt_thread_struct;


int kdump_types_init(void);
void *kdump_type_alloc (struct kdump_type *type, offset addr, int pos, void *buff);
struct kt_list_head;

unsigned long long kt_int_value (void *buff);
unsigned long long kt_ptr_value (void *buff);

int kt_hlist_head_for_each_node (char *addr, int(*func)(void *,offset), void *data);

#define kt_list_head_for_each(addr,head,lhb, _nxt) for((_nxt = kt_ptr_value(lhb)), kdump_type_alloc((struct kdump_type*)&kt_list_head, _nxt, 0, lhb);\
	(_nxt = kt_ptr_value(lhb)) != head; \
	kdump_type_alloc((struct kdump_type*)&kt_list_head, _nxt, 0, lhb))


#endif
