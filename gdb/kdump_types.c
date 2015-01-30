#include "defs.h"
#include "arch-utils.h"
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>		/* needed for F_OK and friends */
#endif
#include "frame.h"		/* required by inferior.h */

#include "symtab.h"
#include "regcache.h"
#include "memattr.h"
#include "language.h"
#include "command.h"
#include "gdbcmd.h"
#include "inferior.h"
#include "infrun.h"
#include "symtab.h"
#include "command.h"
#include "bfd.h"
#include "target.h"
#include "gdbcore.h"
#include "gdbthread.h"
#include "regcache.h"
#include "regset.h"
#include "symfile.h"
#include "exec.h"
#include "readline/readline.h"
#include "exceptions.h"
#include "solib.h"
#include "filenames.h"
#include "progspace.h"
#include "objfiles.h"
#include "gdb_bfd.h"
#include "completer.h"
#include "filestuff.h"
#include "kdump_types.h"

static struct kdump_type *typelist = NULL;

enum {
	T_STRUCT = 1,
	T_BASE,
	T_REF
};


struct type * lookup_struct (const char *name, const struct block *block);
extern struct gdbarch *kdump_gdbarch;

static struct kdump_type *kdump_type_init (void *type, const char *name, const char *origname, int origtype)
{
	struct kdump_type *ktype;
	struct type *t;

	ktype = (struct kdump_type*)type;

	if (origtype == T_STRUCT) 
		t = lookup_struct(origname, NULL);
	else if (origtype == T_REF) {
		struct type *dt;
		dt = lookup_typename(current_language, kdump_gdbarch, origname, NULL, 0);
		if (dt == NULL) {
			fprintf (stderr, "Cannot lookup dereferenced type %s\n", origname);
			t = NULL;
		} else {
			t = lookup_reference_type(dt);
		}
	} else 
		t = lookup_typename(current_language, kdump_gdbarch, origname, NULL, 0);

	if (t == NULL) {
		fprintf(stderr, "Cannot lookup(%s)\n", origname);
		return NULL;
	}

	ktype->name = name;
	ktype->origtype = t;

	ktype->next = typelist;
	typelist = ktype;

	return ktype;
}

#if 0
static struct kdump_type *kdump_type_byname (const char *name)
{
	struct kdump_type *t;

	for (t = typelist; t != NULL && strcmp(name, t->name); t = t->next);

	return (t);
}
#endif


static offset kdump_type_member (struct kdump_type *type, const char *name)
{
	int i;
	struct field *f;
	f = TYPE_FIELDS(type->origtype);
	for (i = 0; i < TYPE_NFIELDS(type->origtype); i ++) {
		if (! strcmp(f->name, name)) return (f->loc.physaddr >> 3);
		f++;
	}
	fprintf(stderr, "Cannot find member \'%s\' for \'%s\'\n", name, type->name);
	return -1;
}

void *kdump_type_alloc (struct kdump_type *type, offset addr, int pos, void *buff);
void *kdump_type_alloc (struct kdump_type *type, offset addr, int pos, void *buff)
{
	int allocated = 0;

	if (buff == NULL) {
		allocated = 1;
		buff = malloc(TYPE_LENGTH(type->origtype));
		if (buff == NULL) {
			fprintf (stderr, "Cannot allocate memory of %d length\n", (int)TYPE_LENGTH(type->origtype));
			return NULL;
		}
	}

	if (target_read_raw_memory(addr + (TYPE_LENGTH(type->origtype)*pos), buff, TYPE_LENGTH(type->origtype))) {
		if (allocated) free(buff);
		fprintf (stderr, "Cannot read target memory of %d length\n", (int)TYPE_LENGTH(type->origtype));
		return NULL;
	}

	return buff;
}


/*
static struct kdump_type *kdump_type_member_init (struct kdump_type *master, const char *name, struct kdump_type *basetype)
{
	struct kdump_type *type;
	struct type *et;

	et = lookup_struct_elt_type (master->origtype, name, 0);

	if (et == NULL) {
		fprintf(stderr, "Cannot find \'%s\' member \'%s\'", master->name, name);
		return NULL;
	}

	printf ("flds_bnds=%p\n", et->main_type);
	printf ("flds_bnds=%p\n", et->main_type->flds_bnds.fields);
	printf ("flds_bnds=%lx\n", et->main_type->flds_bnds.fields->loc.physaddr);
	type = calloc(sizeof (struct kdump_type), 1);
	type->name = name;
	type->mtype = basetype;
	type->mastertype = master;

	return type;
}*/


int kt_hlist_head_for_each_node (char *addr, int(*func)(void *,offset), void *data)
{
	char *b = NULL;
	offset l;
	int i = 0;
	static int cnt = 0;
	static int ccnt = 0;
	ccnt ++;

	l = kt_ptr_value((char*)addr + (size_t)kt_hlist_head.first);
	if (l == NULL_offset) return 0;
	while(l != NULL_offset) {
		
		if (!(b = kdump_type_alloc ((struct kdump_type*)&kt_hlist_node, l, 0, b))) {
			fprintf(stderr, "Cannot kdump_type_alloc(kt_hlist_node)");
			free(b);
			return -1;
		}
		if (func(data, l)) break;
		l = kt_ptr_value((char*)b + (size_t)kt_hlist_node.next);
	}

	if (b) free(b);
	return 0;
}


#define STRUCT_MEMBER_(s,m,mn) do {\
		if((s.m = kdump_type_member((struct kdump_type*)&s, mn)) == -1) break; else ok++; } while(0)
#define STRUCT_MEMBER(s,m) STRUCT_MEMBER_(s,m,#m)

int kdump_types_init(void);
int kdump_types_init(void)
{
	int ok = 1;
	do {
		
		if (!kdump_type_init (&kt_int, "int", "int", T_BASE)) 
			break;

		if (!kdump_type_init (&kt_voidp, "void*", "void", T_REF)) 
			break;

		if (!kdump_type_init (&kt_list_head, "list_head", "list_head", T_STRUCT)) 
			break;

		STRUCT_MEMBER(kt_list_head,prev);

		STRUCT_MEMBER(kt_list_head,next);

		if (!kdump_type_init (&kt_hlist_head, "hlist_head", "hlist_head", T_STRUCT)) 
			break;

		STRUCT_MEMBER(kt_hlist_head,first);

		if (!kdump_type_init (&kt_hlist_node, "hlist_node", "hlist_node", T_STRUCT)) 
			break;

		STRUCT_MEMBER(kt_hlist_node,next);

		if (!kdump_type_init (&kt_upid, "upid", "upid", T_STRUCT)) 

		STRUCT_MEMBER(kt_upid,nr);

		STRUCT_MEMBER(kt_upid,pid_chain);

		if (!kdump_type_init (&kt_task_struct, "task_struct", "task_struct", T_STRUCT)) 
			break;

		STRUCT_MEMBER(kt_task_struct,pids);

		STRUCT_MEMBER(kt_task_struct,stack);

		STRUCT_MEMBER(kt_task_struct,tasks);

		STRUCT_MEMBER(kt_task_struct,thread);

		STRUCT_MEMBER(kt_task_struct,pid);

		STRUCT_MEMBER(kt_task_struct,state);

		STRUCT_MEMBER(kt_task_struct,comm);

		if (!kdump_type_init (&kt_thread_struct, "thread_struct", "thread_struct", T_STRUCT)) 
			break;

		STRUCT_MEMBER(kt_thread_struct,sp);

		ok = 0;
	} while(0);

	if (ok) {
		fprintf(stderr, "Cannot initialize types (%d)\n", ok);
		return ok;
	}

	return ok;
}
					
unsigned long long kt_int_value (void *buff)
{
	unsigned long long val;

	val = *(int*)buff;

	return val;
}

unsigned long long kt_ptr_value (void *buff)
{
	unsigned long long val;
	val = (unsigned long long) *(void**)buff;
	return val;
}

//struct kdump_type *kdump_type_init (void *type, const char *name, size_t siz, const char *origname, int origtype)

