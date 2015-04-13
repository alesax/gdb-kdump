/* Core dump and executable file functions below target vector, for GDB.

 Copyright (C) 1986-2015 Free Software Foundation, Inc.

 This file is part of GDB.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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
#include "s390-linux-tdep.h"
#include "kdumpfile.h"

#include <dirent.h>
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif
typedef unsigned long long offset;
#define NULL_offset 0LL
#define F_BIG_ENDIAN 1

unsigned long long kt_int_value (void *buff);
unsigned long long kt_ptr_value (void *buff);

int kt_hlist_head_for_each_node (char *addr, int(*func)(void *,offset), void *data);

#define kt_list_head_for_each(addr,head,lhb, _nxt) for((_nxt = kt_ptr_value(lhb)), kdump_type_alloc((struct kdump_type*)&kt_list_head, _nxt, 0, lhb);\
	(_nxt = kt_ptr_value(lhb)) != head; \
	kdump_type_alloc((struct kdump_type*)&kt_list_head, _nxt, 0, lhb))

static struct target_ops core_ops;

static kdump_ctx *dump_ctx = NULL;

struct gdbarch *kdump_gdbarch = NULL;

struct target_ops *kdump_target = NULL;

static void init_core_ops (void);

void _initialize_kdump (void);

static void core_close (struct target_ops *self);

typedef unsigned long long offset;

#define KDUMP_TYPE const char *_name; int _size; int _offset; struct type *_origtype
#define GET_GDB_TYPE(typ) types. typ ._origtype
#define GET_TYPE_SIZE(typ) (TYPE_LENGTH(GET_GDB_TYPE(typ)))
#define NULL_offset 0LL
#define F_BIG_ENDIAN 1
#define MEMBER_OFFSET(type,member) types. type. member
#define KDUMP_TYPE_ALLOC(type) kdump_type_alloc(GET_GDB_TYPE(type))
#define KDUMP_TYPE_GET(type,off,where) kdump_type_get(GET_GDB_TYPE(type), off, 0, where)
#define KDUMP_TYPE_FREE(where) free(where)
#define SYMBOL(var,name) do { var = lookup_symbol(name, NULL, VAR_DOMAIN, NULL); if (! var) { fprintf(stderr, "Cannot lookup_symbol(" name ")\n"); goto error; } } while(0)
#define OFFSET(x) (types.offsets. x)

#define MAXSYMNAME 256

#define GET_REGISTER_OFFSET(reg) (MEMBER_OFFSET(user_regs_struct,reg)/GET_TYPE_SIZE(_voidp))
#define GET_REGISTER_OFFSET_pt(reg) (MEMBER_OFFSET(pt_regs,reg)/GET_TYPE_SIZE(_voidp))

#define list_head_for_each(head,lhb, _nxt) for((_nxt = kt_ptr_value(lhb)), KDUMP_TYPE_GET(list_head, _nxt, lhb);\
	(_nxt = kt_ptr_value(lhb)) != head; \
	KDUMP_TYPE_GET(list_head, _nxt, lhb))

enum x86_64_regs {
	reg_RAX = 0,
	reg_RCX = 2,
	reg_RDX = 1,
	reg_RBX = 3,
	reg_RBP = 6,
	reg_RSI = 4,
	reg_RDI = 5,
	reg_RSP = 7,
	reg_R8 = 8,
	reg_R9 = 9,
	reg_R10 = 10,
	reg_R11 = 11,
	reg_R12 = 12,
	reg_R13 = 13,
	reg_R14 = 14,
	reg_R15 = 15,
	reg_RIP = 16,
	reg_RFLAGS = 49,
	reg_ES = 50,
	reg_CS = 51,
	reg_SS = 52,
	reg_DS = 53,
	reg_FS = 54,
	reg_GS = 55,
};

int kt_hlist_head_for_each_node (char *addr, int(*func)(void *,offset), void *data);

typedef enum {
	ARCH_NONE,
	ARCH_X86_64,
	ARCH_S390X
} t_arch;

struct cpuinfo {
	struct {
		offset curr;
	} rq;
};

struct {
	struct {
		KDUMP_TYPE;
		offset prev;
		offset next;
	} list_head;

	struct {
		KDUMP_TYPE;
		offset first;
	} hlist_head;

	struct {
		KDUMP_TYPE;
		offset next;
	} hlist_node;

	struct {
		KDUMP_TYPE;
	} _int;

	struct {
		KDUMP_TYPE;
	} _voidp;

	struct {
		KDUMP_TYPE;

		offset nr;
		offset pid_chain;
	} upid;

	struct {
		KDUMP_TYPE;

		offset pid;
		offset pids;
		offset stack;
		offset tasks;
		offset thread;
		offset state;
		offset comm;
	} task_struct;

	struct {
		KDUMP_TYPE;
		offset sp;
	} thread_struct;

	struct {
		KDUMP_TYPE;
		offset curr;
		offset idle;
	} rq;

	struct {
		KDUMP_TYPE;
		offset r15;
		offset r14;
		offset r13;
		offset r12;
		offset bp;
		offset bx;
		offset r11;
		offset r10;
		offset r9;
		offset r8;
		offset ax;
		offset cx;
		offset dx;
		offset si;
		offset di;
		offset orig_ax;
		offset ip;
		offset cs;
		offset flags;
		offset sp;
		offset ss;
		offset fs_base;
		offset gs_base;
		offset ds;
		offset es;
		offset fs;
		offset gs;
	} user_regs_struct;

	struct pt_regs {
		KDUMP_TYPE;
		offset r15;
		offset r14;
		offset r13;
		offset r12;
		offset bp;
		offset bx;
		offset r11;
		offset r10;
		offset r9;
		offset r8;
		offset ax;
		offset cx;
		offset dx;
		offset si;
		offset di;
		offset orig_ax;
		offset ip;
		offset cs;
		offset flags;
		offset sp;
		offset ss;		
	} pt_regs;


	struct {
		KDUMP_TYPE;
		offset list;
		offset version;
		offset srcversion;
		offset name;
		offset module_core;
	} module;


	int flags;
	t_arch arch;

	struct {
		offset percpu_start;
		offset percpu_end;
		offset *percpu_offsets;
	} offsets;

	struct cpuinfo *cpu;
	int ncpus;
} types;

struct task_info {
	offset task_struct;
	offset sp;
	offset ip;
	int pid;
	int cpu;
	offset rq;
};

enum {
	T_STRUCT = 1,
	T_BASE,
	T_REF
};

static void free_task_info(struct private_thread_info *addr)
{
	struct task_info *ti = (struct task_info*)addr;
	free(ti);
}

unsigned long long kt_int_value (void *buff)
{
	unsigned long long val;

	if (GET_TYPE_SIZE(_int) == 4) {
		val = *(int32_t*)buff;
		if (types.flags & F_BIG_ENDIAN) val = __bswap_32(val);
	} else {
		val = *(int64_t*)buff;
		if (types.flags & F_BIG_ENDIAN) val = __bswap_64(val);
	}

	return val;
}

unsigned long long kt_ptr_value (void *buff)
{
	unsigned long long val;
	
	if (GET_TYPE_SIZE(_voidp) == 4) {
		val = (unsigned long long) *(uint32_t**)buff;
		if (types.flags & F_BIG_ENDIAN) val = __bswap_32(val);
	} else {
		val = (unsigned long long) *(uint64_t**)buff;
		if (types.flags & F_BIG_ENDIAN) val = __bswap_64(val);
	}
	return val;
}

static offset get_symbol_value(const char *sname);
static offset get_symbol_value(const char *sname)
{
	struct symbol *ss;
	const struct language_defn *lang;
	struct value *val;
	offset off;
	ss = lookup_global_symbol(sname, NULL, VAR_DOMAIN);
	if (! ss) {
		ss = lookup_static_symbol(sname, VAR_DOMAIN);
		if (! ss) return NULL_offset ;
	}
	lang  = language_def (SYMBOL_LANGUAGE (ss));
	val = lang->la_read_var_value (ss, NULL);
	if (! val) {
		return NULL_offset;
	}

	if (TYPE_CODE(value_type(val)) == TYPE_CODE_ENUM) {
		return (offset) value_as_long(val);
	} else {
		off = (offset) value_address(val);
		return off;
	}
}

/**
 * Searches the gdb for the type of specified name of the specified kind.
 *
 * @param _type on successfull return contains pointer to type
 * @param size on successfull return contains type size
 * @param origname the name of type
 * @param origtype T_STRUCT or T_REF or T_BASE
 *
 * @return 0 on success
 */
static int kdump_type_init (struct type **_type, int *size, const char *origname, int origtype)
{
	struct type *t;

	if (origtype == T_STRUCT)  {
		t = lookup_struct(origname, NULL);
	} else if (origtype == T_REF) {
		struct type *dt;
 		dt = lookup_typename(current_language, kdump_gdbarch, origname, NULL, 0);
		if (dt == NULL) {
			warning(_("Cannot lookup dereferenced type %s\n"), origname);
			t = NULL;
		} else {
			t = lookup_reference_type(dt);
		}
	} else 
		t = lookup_typename(current_language, kdump_gdbarch, origname, NULL, 0);

	if (t == NULL) {
		warning(_("Cannot lookup(%s)\n"), origname);
		return 1;
	}

	*_type = t;
	*size = TYPE_LENGTH(t);

	return 0;
}

static int kdump_type_member_init (struct type *type, const char *name, offset *poffset)
{
	int i;
	struct field *f;
	f = TYPE_FIELDS(type);
	for (i = 0; i < TYPE_NFIELDS(type); i ++) {
		if (! strcmp(f->name, name)) {
			*poffset = (f->loc.physaddr >> 3);
			return 0;
		}
		f++;
	}
	fprintf(stderr, "Cannot find member \'%s\'\n", name);
	return -1;
}

static void *kdump_type_alloc(struct type *type)
{
	int allocated = 0;
	void *buff;

	allocated = 1;
	buff = malloc(TYPE_LENGTH(type));
	if (buff == NULL) {
		warning(_("Cannot allocate memory of %d length\n"), (int)TYPE_LENGTH(type));
		return NULL;
	}
	return buff;
}

static int kdump_type_get(struct type *type, offset addr, int pos, void *buff)
{
	if (target_read_raw_memory(addr + (TYPE_LENGTH(type)*pos), buff, TYPE_LENGTH(type))) {
		warning(_("Cannot read target memory of %d length\n"), (int)TYPE_LENGTH(type));
		return 1;
	}
	return 0;
}

int kdump_types_init(int flags);
int kdump_types_init(int flags)
{
	int ret = 1;
	
	types.flags = flags;

	#define INIT_STRUCT(name) if(kdump_type_init(&types. name ._origtype, &types. name ._size, #name, T_STRUCT)) { fprintf(stderr, "Cannot find struct type \'%s\'", #name); break; }
	#define INIT_BASE_TYPE(name) if(kdump_type_init(&types. name ._origtype, &types. name ._size, #name, T_BASE)) { fprintf(stderr, "Cannot base find type \'%s\'", #name); break; }
	/** initialize base type and supply its name */
	#define INIT_BASE_TYPE_(name,tname) if(kdump_type_init(&types. tname ._origtype, &types. tname ._size, #name, T_BASE)) { fprintf(stderr, "Cannot base find type \'%s\'", #name); break; }
	#define INIT_REF_TYPE(name) if(kdump_type_init(&types. name ._origtype, &types. name ._size, #name, T_REF)) { fprintf(stderr, "Cannot ref find type \'%s\'", #name); break; }
	#define INIT_REF_TYPE_(name,tname) if(kdump_type_init(&types. tname ._origtype, &types. tname ._size, #name, T_REF)) { fprintf(stderr, "Cannot ref find type \'%s\'", #name); break; }
	#define INIT_STRUCT_MEMBER(sname,mname) if(kdump_type_member_init(types. sname ._origtype, #mname, &types. sname . mname)) { break; }

	/** initialize member with different name than the containing one */
	#define INIT_STRUCT_MEMBER_(sname,mname,mmname) if(kdump_type_member_init(types. sname ._origtype, #mname, &types. sname . mmname)) { break; }

	/** don't fail if the member is not present */
	#define INIT_STRUCT_MEMBER__(sname,mname) kdump_type_member_init(types. sname ._origtype, #mname, &types. sname . mname)
	do {
		INIT_BASE_TYPE_(int,_int); 
		INIT_REF_TYPE_(void,_voidp); 

		INIT_STRUCT(list_head); 
		INIT_STRUCT_MEMBER(list_head,prev);
		INIT_STRUCT_MEMBER(list_head,next);

		INIT_STRUCT(hlist_head); 
		INIT_STRUCT_MEMBER(hlist_head,first);

		INIT_STRUCT(hlist_node); 
		INIT_STRUCT_MEMBER(hlist_node,next);

		INIT_STRUCT(upid); 
		INIT_STRUCT_MEMBER(upid,nr);
		INIT_STRUCT_MEMBER(upid,pid_chain);

		INIT_STRUCT(task_struct); 
		INIT_STRUCT_MEMBER(task_struct,pids);
		INIT_STRUCT_MEMBER(task_struct,stack);
		INIT_STRUCT_MEMBER(task_struct,tasks);
		INIT_STRUCT_MEMBER(task_struct,thread);
		INIT_STRUCT_MEMBER(task_struct,pid);
		INIT_STRUCT_MEMBER(task_struct,state);
		INIT_STRUCT_MEMBER(task_struct,comm);

		INIT_STRUCT(thread_struct); 
                MEMBER_OFFSET(thread_struct,sp) = 0;
		INIT_STRUCT_MEMBER__(thread_struct,sp);
                if (MEMBER_OFFSET(thread_struct,sp) == 0) {
			INIT_STRUCT_MEMBER_(thread_struct,ksp,sp);
		}

		INIT_STRUCT(rq); 

		INIT_STRUCT_MEMBER(rq,curr);
		INIT_STRUCT_MEMBER(rq,idle);

		INIT_STRUCT(user_regs_struct);
		INIT_STRUCT_MEMBER__(user_regs_struct, r15);
		INIT_STRUCT_MEMBER__(user_regs_struct, r14);
		INIT_STRUCT_MEMBER__(user_regs_struct, r13);
		INIT_STRUCT_MEMBER__(user_regs_struct, r12);
		INIT_STRUCT_MEMBER__(user_regs_struct, bp);
		INIT_STRUCT_MEMBER__(user_regs_struct, bx);
		INIT_STRUCT_MEMBER__(user_regs_struct, r11);
		INIT_STRUCT_MEMBER__(user_regs_struct, r10);
		INIT_STRUCT_MEMBER__(user_regs_struct, r9);
		INIT_STRUCT_MEMBER__(user_regs_struct, r8);
		INIT_STRUCT_MEMBER__(user_regs_struct, ax);
		INIT_STRUCT_MEMBER__(user_regs_struct, cx);
		INIT_STRUCT_MEMBER__(user_regs_struct, dx);
		INIT_STRUCT_MEMBER__(user_regs_struct, si);
		INIT_STRUCT_MEMBER__(user_regs_struct, di);
		INIT_STRUCT_MEMBER__(user_regs_struct, orig_ax);
		INIT_STRUCT_MEMBER__(user_regs_struct, ip);
		INIT_STRUCT_MEMBER__(user_regs_struct, cs);
		INIT_STRUCT_MEMBER__(user_regs_struct, flags);
		INIT_STRUCT_MEMBER__(user_regs_struct, sp);
		INIT_STRUCT_MEMBER__(user_regs_struct, ss);
		INIT_STRUCT_MEMBER__(user_regs_struct, fs_base);
		INIT_STRUCT_MEMBER__(user_regs_struct, gs_base);
		INIT_STRUCT_MEMBER__(user_regs_struct, ds);
		INIT_STRUCT_MEMBER__(user_regs_struct, es);
		INIT_STRUCT_MEMBER__(user_regs_struct, fs);
		INIT_STRUCT_MEMBER__(user_regs_struct, gs);
	
		INIT_STRUCT(pt_regs);
		INIT_STRUCT_MEMBER__(pt_regs, r15);
		INIT_STRUCT_MEMBER__(pt_regs, r14);
		INIT_STRUCT_MEMBER__(pt_regs, r13);
		INIT_STRUCT_MEMBER__(pt_regs, r12);
		INIT_STRUCT_MEMBER__(pt_regs, bp);
		INIT_STRUCT_MEMBER__(pt_regs, bx);
		INIT_STRUCT_MEMBER__(pt_regs, r11);
		INIT_STRUCT_MEMBER__(pt_regs, r10);
		INIT_STRUCT_MEMBER__(pt_regs, r9);
		INIT_STRUCT_MEMBER__(pt_regs, r8);
		INIT_STRUCT_MEMBER__(pt_regs, ax);
		INIT_STRUCT_MEMBER__(pt_regs, cx);
		INIT_STRUCT_MEMBER__(pt_regs, dx);
		INIT_STRUCT_MEMBER__(pt_regs, si);
		INIT_STRUCT_MEMBER__(pt_regs, di);
		INIT_STRUCT_MEMBER__(pt_regs, orig_ax);
		INIT_STRUCT_MEMBER__(pt_regs, ip);
		INIT_STRUCT_MEMBER__(pt_regs, cs);
		INIT_STRUCT_MEMBER__(pt_regs, flags);
		INIT_STRUCT_MEMBER__(pt_regs, sp);
		INIT_STRUCT_MEMBER__(pt_regs, ss);

		INIT_STRUCT(module);
		INIT_STRUCT_MEMBER(module, list);
		INIT_STRUCT_MEMBER(module, version);
		INIT_STRUCT_MEMBER(module, srcversion);
		INIT_STRUCT_MEMBER(module, name);
		INIT_STRUCT_MEMBER(module, module_core);
		ret = 0;
	} while(0);

	if (ret) {
		fprintf(stderr, "Cannot init types\n");
	}

	return ret;
}

int kt_hlist_head_for_each_node (char *addr, int(*func)(void *,offset), void *data)
{
	char *b = NULL;
	offset l;
	int i = 0;
	static int cnt = 0;
	static int ccnt = 0;
	ccnt ++;

	b = KDUMP_TYPE_ALLOC(hlist_node);

	l = kt_ptr_value((char*)addr + (size_t)MEMBER_OFFSET(hlist_head,first));
	if (l == NULL_offset) return 0;
	while(l != NULL_offset) {
		
		if (KDUMP_TYPE_GET (hlist_node, l, b)) {
			fprintf(stderr, "Cannot kdump_type_alloc(kt_hlist_node)");
			KDUMP_TYPE_FREE(b);
			return -1;
		}
		if (func(data, l)) break;
		l = kt_ptr_value((char*)b + (size_t)MEMBER_OFFSET(hlist_node,next));
	}

	if (b) free(b);
	return 0;
}

static void
core_close (struct target_ops *self)
{
	if (dump_ctx != NULL) {
		kdump_free(dump_ctx);
		dump_ctx = NULL;
	}

	kdump_gdbarch = NULL;
}

static int init_types(int);
static int init_types(int flags)
{
	struct type *t, *et;
	int i, nc, r;
	kdump_reg_t reg;

	nc = kdump_num_cpus(dump_ctx);
	types.ncpus = kdump_num_cpus(dump_ctx);

	for (i = 0; i < nc; i++) {
		for (r = 0; ; r++) {
			if (kdump_read_reg(dump_ctx, i, r, &reg)) break;
#ifdef _DEBUG
			printf_filtered("CPU % 2d,REG%02d=%llx\n", i, r, (long long unsigned int)reg);
#endif
		}
	}

	return kdump_types_init(flags);
}

static offset get_percpu_offset(const char *varname, int ncpu);
static offset get_percpu_offset(const char *varname, int ncpu)
{
	char buff[MAXSYMNAME];
	char b[sizeof(offset)];
	struct symbol *sym;
	offset off = NULL_offset;

	snprintf(buff, sizeof(buff)-1, "%s", varname);

	do {
		off = get_symbol_value(buff);
		if (off >= OFFSET(percpu_start) && off <= OFFSET(percpu_end)) {
			off = off + OFFSET(percpu_offsets[ncpu]);
			break;
		}

		sym = lookup_global_symbol(buff, NULL, VAR_DOMAIN);
		if (sym && sym->is_objfile_owned && sym->owner.symtab->compunit_symtab) {
			struct obj_section *os;
			os = SYMBOL_OBJ_SECTION(sym->owner.symtab->compunit_symtab->objfile, sym);

			if (os->the_bfd_section && !strcmp(os->the_bfd_section->name, ".data..percpu")) {
				off = off + OFFSET(percpu_offsets[ncpu]);
				break;
			}
		}

	} while(0);

	return off;
}

static void init_runqueues(void);
static void init_runqueues(void)
{
	int i;
	offset r, curr;
	char *runq;

	runq = KDUMP_TYPE_ALLOC(rq);

	for(i = 0; i < types.ncpus; i++) {
		r = get_percpu_offset("runqueues", i);
		if (r == NULL_offset) {
			error(_("Cannot get pcpu offset of \'runqueues\':%d\n"), i);
			goto out;
		}
		if (KDUMP_TYPE_GET(rq, r, runq)) {
			error(_("Cannot get runqueue\n"));
			goto out;
		}
		curr = kt_ptr_value(runq + MEMBER_OFFSET(rq,curr));

		types.cpu[i].rq.curr = curr;
#ifdef _DEBUG
		printf_filtered("cpu%02d->curr=%llx\n", i, curr);
#endif
	}
out:
	KDUMP_TYPE_FREE(runq);
}

/**
 * Return the index of CPU that runs specifed task, or -1.
 * 
 */
static int get_process_cpu(offset task);
static int get_process_cpu(offset task)
{
	int i;

	for(i = 0; i < types.ncpus; i++) {
		if (types.cpu[i].rq.curr == task) return i;
	}

	return -1;
}

static int init_values(void);
static int init_values(void)
{
	struct symbol *s;
	char *b = NULL, *init_task = NULL, *task = NULL;
	offset off, off_task, rsp, rip, _rsp;
	offset tasks;
	offset stack;
	offset o_init_task;
	int state;
	int i, cpu;
	int hashsize;
	struct inferior *in;
	int cnt = 0;
	int pid_reserve;
	struct task_info *task_info;

	s = NULL;
	
	b = KDUMP_TYPE_ALLOC(_voidp);
	if (!b) goto error;

	OFFSET(percpu_start) = get_symbol_value("__per_cpu_start");
	OFFSET(percpu_end) = get_symbol_value("__per_cpu_end");
	off = get_symbol_value("__per_cpu_offset");
	types.cpu = malloc(sizeof(struct cpuinfo)*types.ncpus);
	OFFSET(percpu_offsets) = malloc(sizeof(offset)*types.ncpus);
	memset(OFFSET(percpu_offsets), 0, sizeof(offset)*types.ncpus);

	for (i = 0; i < types.ncpus; i++) {
		if (KDUMP_TYPE_GET(_voidp, off + GET_TYPE_SIZE(_voidp)*i, b)) goto error;
		OFFSET(percpu_offsets[i]) = kt_ptr_value(b);
#ifdef _DEBUG
		printf ("pcpu[%d]=%llx\n", i, OFFSET(percpu_offsets[i]));
#endif
	}

	init_runqueues();

	o_init_task = get_symbol_value("init_task");
	if (! o_init_task) {
		warning(_("Cannot find init_task\n"));
		return -1;
	}
	init_task = KDUMP_TYPE_ALLOC(task_struct);
	if (!init_task) 
		goto error;
	task = KDUMP_TYPE_ALLOC(task_struct);
	if (!task) goto error;
	if (KDUMP_TYPE_GET(task_struct, o_init_task, init_task)) 
		goto error;
	tasks = kt_ptr_value(init_task + MEMBER_OFFSET(task_struct,tasks));

	i = 0;
	off = 0;
	pid_reserve = 50000;

	print_thread_events = 0;
	in = current_inferior();
	inferior_appeared (in, 1);

	list_head_for_each(tasks, init_task + MEMBER_OFFSET(task_struct,tasks), off) {
		struct thread_info *info;
		int pid;
		ptid_t tt;
		struct regcache *rc;
		long long val;

		off_task = off - MEMBER_OFFSET(task_struct,tasks);
		if (KDUMP_TYPE_GET(task_struct, off_task, task)) goto error;

		state = kt_int_value(task + MEMBER_OFFSET(task_struct,state));
		pid = kt_int_value(task + MEMBER_OFFSET(task_struct,pid));
		stack = kt_ptr_value(task + MEMBER_OFFSET(task_struct,stack));
		_rsp = rsp = kt_ptr_value(task + MEMBER_OFFSET(task_struct,thread) + MEMBER_OFFSET(thread_struct,sp));

		if (pid == 0) pid = pid_reserve++;
		task_info = malloc(sizeof(struct task_info));
		task_info->pid = pid;
		task_info->cpu = -1;

		if (types.arch == ARCH_S390X) {
			if (! KDUMP_TYPE_GET(_voidp, rsp+136, b)) 
				rip = kt_ptr_value(b);
			if (KDUMP_TYPE_GET(_voidp, rsp+144, b)) goto error;
			rsp = kt_ptr_value(b);
			task_info->sp = rsp;
			task_info->ip = rip;
		} else {
			if (KDUMP_TYPE_GET(_voidp, rsp, b)) goto error;
			rip = kt_ptr_value(b);
		}
#ifdef _DEBUG
		fprintf(stdout, "TASK %llx,%llx,rsp=%llx,rip=%llx,pid=%d,state=%d,name=%s\n", off_task, stack, rsp, rip, pid, state, task + MEMBER_OFFSET(task_struct,comm));
#endif
		if (pid < 0) {
			free_task_info((struct private_thread_info*)task_info);
			continue;
		}

		task_info->task_struct = off_task;

		tt = ptid_build (1, pid, 0);
		info = add_thread(tt);
		info->private = (struct private_thread_info*)task_info;
		info->private_dtor = free_task_info;

		inferior_ptid = tt;
		info->name = strdup(task + MEMBER_OFFSET(task_struct,comm));
	
		val = 0;
		cnt ++;

		rc = get_thread_regcache (tt);

		if (types.arch == ARCH_S390X) {

			/*
			 * TODO: implement retrieval of register values from lowcore 
			 */
			val = __bswap_64(rip); 
			regcache_raw_supply(rc, 1, &val);

			if (! KDUMP_TYPE_GET(_voidp, _rsp+136, b)) regcache_raw_supply(rc, S390_R14_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+128, b)) regcache_raw_supply(rc, S390_R13_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+120, b)) regcache_raw_supply(rc, S390_R12_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+112, b)) regcache_raw_supply(rc, S390_R11_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+104, b)) regcache_raw_supply(rc, S390_R10_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+96, b)) regcache_raw_supply(rc, S390_R9_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+88, b)) regcache_raw_supply(rc, S390_R8_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+80, b)) regcache_raw_supply(rc, S390_R7_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+72, b)) regcache_raw_supply(rc, S390_R6_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+64, b)) regcache_raw_supply(rc, S390_R5_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+56, b)) regcache_raw_supply(rc, S390_R4_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+48, b)) regcache_raw_supply(rc, S390_R3_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+40, b)) regcache_raw_supply(rc, S390_R2_REGNUM, b); 
			if (! KDUMP_TYPE_GET(_voidp, _rsp+32, b)) regcache_raw_supply(rc, S390_R1_REGNUM, b); 
			
			val = __bswap_64(rsp);
			regcache_raw_supply(rc, S390_R15_REGNUM, &val);
		} else if (types.arch == ARCH_X86_64) {
			/* 
			 * The task is not running - e.g. crash would show it's stuck in schedule()
			 * Yet schedule() is not on its stack.
			 *
			 */
			cpu = 0;
			if (((cpu = get_process_cpu(off_task)) == -1)) {
				long long regs[64];

				/*
				 * So we're gonna skip its stackframe
				 * FIXME: use the size obtained from debuginfo
				 */
				rsp += 0x148;
				target_read_raw_memory(rsp - 0x8 * (1 + 6), (void*)regs, 0x8 * 6);

				regcache_raw_supply(rc, 15, &regs[5]);
				regcache_raw_supply(rc, 14, &regs[4]);
				regcache_raw_supply(rc, 13, &regs[3]);
				regcache_raw_supply(rc, 12, &regs[2]);
				regcache_raw_supply(rc, 6, &regs[1]);
				regcache_raw_supply(rc, 3, &regs[0]);

				KDUMP_TYPE_GET(_voidp, rsp, b);
				rip = kt_ptr_value(b);
				rsp += 8;

				regcache_raw_supply(rc, 7, &rsp);
				regcache_raw_supply(rc, 16, &rip);

				task_info->sp = rsp;
				task_info->ip = rip;
			} else {
				kdump_reg_t reg;

				task_info->cpu = cpu;
#ifdef _DEBUG
				printf("task is running on %d\n", cpu);
#endif

#define REG(en,mem) kdump_read_reg(dump_ctx, cpu, GET_REGISTER_OFFSET(mem), &reg); regcache_raw_supply(rc, en, &reg)
			
				REG(reg_RSP,sp);
				task_info->sp = reg;
				REG(reg_RIP,ip);
				task_info->ip = reg;
				REG(reg_RAX,ax);
				REG(reg_RCX,cx);
				REG(reg_RDX,dx);
				REG(reg_RBX,bx);
				REG(reg_RBP,bp);
				REG(reg_RSI,si);
				REG(reg_RDI,di);
				REG(reg_R8,r8);
				REG(reg_R9,r9);
				REG(reg_R10,r10);
				REG(reg_R11,r11);
				REG(reg_R12,r12);
				REG(reg_R13,r13);
				REG(reg_R14,r14);
				REG(reg_R15,r15);
				REG(reg_RFLAGS,flags);
				REG(reg_ES,es);
				REG(reg_CS,cs);
				REG(reg_SS,ss);
				REG(reg_DS,ds);
				REG(reg_FS,fs);
				REG(reg_GS,gs);
#undef REG
			}
		}
		printf_unfiltered(_("Loaded processes: %d\r"), cnt);
	}

	if (b) free(b);
	if (init_task) free(init_task);

	printf_unfiltered(_("Loaded processes: %d\n"), cnt);
	return 0;
error:
	if (b) free(b);
	if (init_task) free(init_task);

	return 1;
}

static int kdump_do_init(void);
static int kdump_do_init(void)
{
	const bfd_arch_info_type *ait;
	struct gdbarch_info gai;
	struct gdbarch *garch;
	struct inferior *inf;
	const char *archname;
	ptid_t tt;

	struct {
		char *kdident;
		char *gdbident;
		int flags;
		t_arch arch;
	} *a, archlist[] = {
		{"x86_64", "i386:x86-64", 0, ARCH_X86_64},
		{"s390x",  "s390:64-bit", 1, ARCH_S390X},
		{NULL}
	};

	archname = kdump_arch_name(dump_ctx);
	if (! archname) {
		error(_("The architecture could not be identified"));
		return -1;
	}
	for (a = archlist; a->kdident && strcmp(a->kdident, archname); a++);

	if (! a->kdident) {
		error(_("Architecture %s is not yet supported by gdb-kdump\n"), archname);
		return -2;
	}

	gdbarch_info_init(&gai);
	ait = bfd_scan_arch (a->gdbident);
	if (! ait) {
		error(_("Architecture %s not supported in gdb\n"), a->gdbident);
		return -3;
	}
	gai.bfd_arch_info = ait;
	garch = gdbarch_find_by_info(gai);
	kdump_gdbarch = garch; 
#ifdef _DEBUG
	fprintf(stderr, "arch=%s,ait=%p,garch=%p\n", selected_architecture_name(), ait, garch);
#endif
	init_thread_list();
	inf = current_inferior();

	types.arch = a->arch;
	
	if (init_types(a->flags)) {
		warning(_("kdump: Cannot init types!\n"));
	}
	if (init_values()) {
		warning(_("kdump: Cannot init values!\n"));
	}
	set_executing(minus_one_ptid,0);
	reinit_frame_cache();

	return 0;
}

static void
kdump_open (const char *arg, int from_tty)
{
	const char *p;
	int siggy;
	struct cleanup *old_chain;
	char *temp;
	bfd *temp_bfd;
	int scratch_chan;
	int flags;
	volatile struct gdb_exception except;
	char *filename;
	int fd;

	target_preopen (from_tty);
	if (!arg) {
		if (core_bfd)
			error (_("No kdump file specified.  (Use `detach' "
				"to stop debugging a core file.)"));
		else
			error (_("No kdump file specified."));
	}

	filename = tilde_expand (arg);
	if (!IS_ABSOLUTE_PATH (filename))
	{
		temp = concat (current_directory, "/", filename, (char *) NULL);
		xfree (filename);
		filename = temp;
	}
	if ((fd = open(filename, O_RDONLY)) == -1) {
		error(_("\"%s\" cannot be opened: %s\n"), filename, strerror(errno));
		return;
	}

	if (kdump_fdopen(&dump_ctx, fd) != kdump_ok) {
		error(_("\"%s\" cannot be opened as kdump\n"), filename);
		return;
	}

	if (kdump_vtop_init(dump_ctx) != kdump_ok) {
		error(_("Cannot kdump_vtop_init(%s)\n"), kdump_err_str(dump_ctx));
		return;
	}

	old_chain = make_cleanup (xfree, filename);

	flags = O_BINARY | O_LARGEFILE;
	if (write_files)
		flags |= O_RDWR;
	else
		flags |= O_RDONLY;
	scratch_chan = gdb_open_cloexec (filename, flags, 0);
	if (scratch_chan < 0)
		perror_with_name (filename);

	push_target (&core_ops);
	
	if (kdump_do_init()) {
		error(_("Cannot initialize kdump"));
	}

	return;
}

static void
core_detach (struct target_ops *ops, const char *args, int from_tty)
{
	if (args)
		error (_("Too many arguments"));
	unpush_target (ops);
	reinit_frame_cache ();
	if (from_tty)
		printf_filtered (_("No core file now.\n"));
}

static kdump_paddr_t transform_memory(kdump_paddr_t addr);
static kdump_paddr_t transform_memory(kdump_paddr_t addr)
{
	kdump_paddr_t out;
	if (kdump_ok == kdump_vtop(dump_ctx, addr, &out)) return out;
	return addr;
}

static enum target_xfer_status
kdump_xfer_partial (struct target_ops *ops, enum target_object object,
			 const char *annex, gdb_byte *readbuf,
			 const gdb_byte *writebuf, ULONGEST offset,
			 ULONGEST len, ULONGEST *xfered_len)
{
	ULONGEST i;
	size_t r;
	if (dump_ctx == NULL) {
		error(_("dump_ctx == NULL\n")); 
	}
	switch (object)
	{
		case TARGET_OBJECT_MEMORY:
			offset = transform_memory((kdump_paddr_t)offset);
			r = kdump_read(dump_ctx, (kdump_paddr_t)offset, (unsigned char*)readbuf, (size_t)len, KDUMP_PHYSADDR);
			if (r != len) {
				error(_("Cannot read %lu bytes from %lx (%lld)!"), (size_t)len, (long unsigned int)offset, (long long)r);
			} else 
				*xfered_len = len;

			return TARGET_XFER_OK;

		default:
			return ops->beneath->to_xfer_partial (ops->beneath, object,
				annex, readbuf,
				writebuf, offset, len,
				xfered_len);
	}
}

static int ignore (struct target_ops *ops, struct gdbarch *gdbarch, struct bp_target_info *bp_tgt)
{
	return 0;
}

static int
core_thread_alive (struct target_ops *ops, ptid_t ptid)
{
	return 1;
}

static const struct target_desc *
core_read_description (struct target_ops *target)
{
	if (kdump_gdbarch && gdbarch_core_read_description_p (kdump_gdbarch))
	{
		const struct target_desc *result;

		result = gdbarch_core_read_description (kdump_gdbarch, target, core_bfd);
		if (result != NULL) return result;
	}

	return target->beneath->to_read_description (target->beneath);
}

static int core_has_memory (struct target_ops *ops)
{
	return 1;
}

static int core_has_stack (struct target_ops *ops)
{
	return 1;
}

static int core_has_registers (struct target_ops *ops)
{
	return 1;
}

#ifdef _DEBUG
void kdumptest_file_command (char *filename, int from_tty);
void kdumptest_file_command (char *filename, int from_tty)
{
	const char *sname = "default_llseek";
	struct symbol *ss;
	const struct language_defn *lang;
	struct value *val;
	struct objfile *obj;
	struct symtab_and_line sal;
	CORE_ADDR addr;
	ss = lookup_global_symbol(sname, NULL, FUNCTIONS_DOMAIN);
	if (! ss) {
		return;
	}
	lang  = language_def (SYMBOL_LANGUAGE (ss));
	val = lang->la_read_var_value (ss, NULL);
	if (! val) {
		return;
	}
	addr = value_address(val);
	printf("symbol = %llx\n", (unsigned long long)addr);

	ss = lookup_static_symbol("modules", VAR_DOMAIN);
	printf("MOD:symbol = %llx\n", (unsigned long long)ss);

	sal = find_pc_line (addr, 0);     
	if (sal.line) {
		if (sal.objfile) {
			if (sal.objfile->original_name)
				printf("original name = %s\n", sal.objfile->original_name);
			printf("sal.objfile=%p\n", sal.objfile);
		} 
		if (sal.section) {
			if (sal.section->objfile) {
				if (sal.section->objfile->original_name)
					printf("original name = %s\n", sal.section->objfile->original_name);
				printf("sal.section->objfile=%p\n", sal.section->objfile);
			} else {
				if (sal.section->the_bfd_section) {
					printf("bfd_section\n");
				} else 
					printf("nothing\n");
			}
		} else {
			printf("no section\n");
		}
		if (sal.symtab && sal.symtab->filename) {
			printf("symtab->filename=%s\n", sal.symtab->filename);
		}

		printf ("line=%d,pc=%llx,end=%llx\n", sal.line, (offset)sal.pc, (offset)sal.end);
	} 
	{
		struct symbol *ss;
		const struct language_defn *lang;
		struct value *val;
		struct obj_section *os;
		ss = lookup_global_symbol("runqueues", NULL, VAR_DOMAIN);
		if (! ss) {
			return;
		}
		printf("sect %d\n", SYMBOL_SECTION(ss));
		//os = SYMBOL_OBJ_SECTION(ss);
		if (ss->is_objfile_owned) {
			printf("symtab=%p\n", ss->owner.symtab);
			if (ss->owner.symtab->compunit_symtab) {
				printf ("objfile %p\n", ss->owner.symtab->compunit_symtab->objfile);
				os = SYMBOL_OBJ_SECTION(ss->owner.symtab->compunit_symtab->objfile, ss);
				if (os->the_bfd_section) {
					printf("bfd yes! \'%s\'\n", os->the_bfd_section->name);
				}
			}
		}
	}

	printf ("percpu(runqueues,1)=%llx\n", get_percpu_offset("runqueues",1));

	printf("sp_regnum=%d\n", gdbarch_sp_regnum(kdump_gdbarch));
	if (gdbarch_unwind_sp_p (kdump_gdbarch))
		printf("gdbarch_unwind_sp_p=TRUE\n");

	fflush(stdout);
	printf("PG_slab=%llx\n", get_symbol_value("PG_slab"));
	return;
}
#endif

void kdump_file_command (char *filename, int from_tty);
void kdump_file_command (char *filename, int from_tty)
{
	dont_repeat ();

	gdb_assert (kdump_target != NULL);

	if (!filename)
		(kdump_target->to_detach) (kdump_target, filename, from_tty);
	else
		(kdump_target->to_open) (filename, from_tty);
}

/**
 * The following code is meant to just search the given path
 * for the modules debuginfo files.
 */
struct t_directory {
	char *name;
	struct t_directory *parent;
	struct t_directory *next;
	struct t_directory *_next;
};

struct t_node {
	char *filename;
	struct t_node *lt;
	struct t_node *gt;
	struct t_directory *parent;
	struct t_node *_next;
};

static struct t_node *rootnode;
static struct t_directory rootdir;
static char rootname[NAME_MAX];
static struct t_node *nodelist;

static void putname(char *path, struct t_directory *dir)
{
	char *v, *c = path;
	for (v = path; dir; dir = dir->parent) {
		const char *e = dir->name + strlen(dir->name) - 1;
		*v++ = '/';
		while (e >= dir->name)
			*v++ = *e--;
	}
	*v-- = '\0';
	while (v > path) {
		char z = *v;
		*v = *path;
		*path = z;
		v --;
		path ++;
	}
}

static void insertnode(struct t_node *node, struct t_node **where)
{
	while(* where) {
		int ret = strcmp(node->filename, (*where)->filename);
		if (ret < 0) where = & (*where)->lt;
		else if (ret > 0) where = & (*where)->gt;
		else break;
	}
	* where = node;
	return;
}

/**
 * Finds the file of the given name (only the files', not full path).
 * If found, it puts its full path in output and returns !NULL .
 * If not found, it returns NULL.
 */
static const char *find_module(const char *name, char *output)
{
	struct t_node *nod = rootnode;
	int ret;

	while(nod && (ret = strcmp(nod->filename, name)) != 0) {
		if (ret > 0) nod = nod->lt;
		else if (ret < 0) nod = nod->gt;
	}
	if (! nod) return NULL;
	putname(output, nod->parent);
	strcat(output, nod->filename);
	return output;
}

static void free_module_list(void)
{
	struct t_directory *n, *p;
	struct t_node *no, *po;
	
	for (n = rootdir._next; ; n = p) {
		if (!n) break;
		p = n->_next;
		if (n->name) free (n->name);
		free (n);
	}

	for (no = nodelist; ; no = po) {
		if (!no) break;
		po = no->_next;
		if (no->filename) free (no->filename);
		free (no);
	}

	rootdir._next = NULL;
	nodelist = NULL;
}

/** 
 * Init the list of modules - walk through p_path and remember
 * all the regular files with names ending on p_suffix.
 */
static void init_module_list(const char *p_path, const char *p_suffix)
{
	char path[NAME_MAX];
	struct t_directory *di;
	int suffixlen;
	DIR *d;

	suffixlen = strlen(p_suffix);
	rootnode = NULL;
	nodelist = NULL;
	di = &rootdir;
	snprintf(rootname, sizeof(rootname)-1, "%s", p_path);
	rootdir.name = rootname;
	rootdir.parent = NULL;
	rootdir.next = NULL;

	while(di) {
		struct dirent en, *_en;
		putname(path, di);
		d = opendir(path);
		if (!d) {
			error(_("Cannot open dir %s!\n"), path);
			return;
		}
		while (! readdir_r(d, &en, &_en) && (_en)) {
			if (en.d_name[0] == '.') continue;
			if (en.d_type == DT_DIR) {
				struct t_directory *ndi = malloc(sizeof(struct t_directory));
				ndi->_next = rootdir._next;
				rootdir._next = ndi;
				ndi->next = di->next;
				ndi->name = strdup(en.d_name);
				ndi->parent = di;
				di->next = ndi;
			} else if (en.d_type == DT_REG) {
				int l = strlen(en.d_name);

				if (l > suffixlen && !strcmp(en.d_name+l-suffixlen, p_suffix)) {
					struct t_node *nod = malloc(sizeof(struct t_node));
					nod->_next = nodelist;
					nodelist = nod;
					nod->filename = strdup(en.d_name);
					nod->parent = di;
					nod->lt = nod->gt = NULL;
					insertnode(nod, &rootnode);
				} 
			}
		}
		closedir(d);
		di = di->next;
	}
}

static void kdumpmodules_command (char *filename, int from_tty);
static void kdumpmodules_command (char *filename, int from_tty)
{
	offset sym_modules, modules, mod, off_mod, addr;
	char *module = NULL;
	char *v = NULL;
	char modulename[56+9+1];
	char modulepath[NAME_MAX];
	int flags = OBJF_USERLOADED | OBJF_SHARED;
	struct section_addr_info *section_addrs;
	struct objfile *objf;

	if (dump_ctx == NULL) {
		error(_("dump_ctx == NULL\n")); 
	}
	if (! filename || ! strlen(filename)) {
		error(_("Specify name of directory to load the modules debuginfo from"));
	}
	section_addrs = alloc_section_addr_info (1);
	section_addrs->other[0].name = ".text";

	/* search the path for modules */
	init_module_list(filename, ".ko.debug");
	module = KDUMP_TYPE_ALLOC(module);
	v = KDUMP_TYPE_ALLOC(_voidp);
	sym_modules = get_symbol_value("modules");
	if(KDUMP_TYPE_GET(_voidp, sym_modules, v)) goto error;
	modules = kt_ptr_value(v);

	/* now walk through the module list (of the dumped kernel) and for each module
	 * try to find it's debuginfo file */
	list_head_for_each(modules, v, mod) {
		if (mod == sym_modules) break;
		off_mod = mod - MEMBER_OFFSET(module,list);
		if(KDUMP_TYPE_GET(module, off_mod, module)) goto error;
		snprintf(modulename, sizeof(modulename)-1, "%s.ko.debug", module + MEMBER_OFFSET(module,name));
		if (! find_module(modulename, modulepath)) {
			warning(_("Cannot find debuginfo file for module \"%s\""), modulename);
			continue;
		}
		addr = kt_ptr_value(module + MEMBER_OFFSET(module,module_core));
#ifdef _DEBUG
		fprintf(stderr, "Going to load module %s at %llx\n", modulepath, addr);
#endif
		section_addrs->other[0].addr = addr;
		section_addrs->num_sections = 1;

		/* load the module' debuginfo (at its module_core address) */
		objf = symbol_file_add (modulepath, from_tty ? SYMFILE_VERBOSE : 0,
				  section_addrs, flags);
		add_target_sections_of_objfile (objf);
	}
	
	error:

	if (v) free(v);
	if (module) free(module);
	free_module_list();
}

static void kdumpps_command(char *fn, int from_tty);
static void kdumpps_command(char *fn, int from_tty)
{
	struct thread_info *tp;
	struct task_info *task;
	char cpu[6];

	if (dump_ctx == NULL) {
		error(_("dump_ctx == NULL\n")); 
	}
	for (tp = thread_list; tp; tp = tp->next) {
		task = (struct task_info*)tp->private;
		if (!task) continue;
		if (task->cpu == -1) cpu[0] = '\0';
		else snprintf(cpu, 5, "% 4d", task->cpu);
		printf_filtered(_("% 7d %llx %llx %llx %-4s %s\n"), task->pid, task->task_struct, task->ip, task->sp, cpu, tp->name);
	}
}

static char *
kdump_pid_to_str (struct target_ops *ops, ptid_t ptid)
{
	static char buf[32];
	xsnprintf (buf, sizeof buf, "pid %ld", ptid_get_lwp (ptid));
	return buf;
}

struct cmd_list_element *kdumplist = NULL;
static void init_core_ops (void)
{
	struct cmd_list_element *c;
	core_ops.to_shortname = "kdump";
	core_ops.to_longname = "Compressed kdump file";
	core_ops.to_doc =
		"Use a vmcore file as a target.  Specify the filename of the vmcore file.";
	core_ops.to_open = kdump_open;
	core_ops.to_close = core_close;
	core_ops.to_detach = core_detach;
	core_ops.to_xfer_partial = kdump_xfer_partial;
	core_ops.to_insert_breakpoint = ignore;
	core_ops.to_remove_breakpoint = ignore;
	core_ops.to_thread_alive = core_thread_alive;
	core_ops.to_read_description = core_read_description;
	core_ops.to_stratum = process_stratum;
	core_ops.to_has_memory = core_has_memory;
	core_ops.to_has_stack = core_has_stack;
	core_ops.to_has_registers = core_has_registers;
	core_ops.to_magic = OPS_MAGIC;
	core_ops.to_pid_to_str = kdump_pid_to_str;

	if (kdump_target)
		internal_error (__FILE__, __LINE__, 
			_("init_kdump_ops: core target already exists (\"%s\")."),
			kdump_target->to_longname);

	kdump_target = &core_ops;

	c = add_prefix_cmd ("kdump", no_class, kdumpmodules_command, 
		_("Commands for ease work with kernel dump target"),
		&kdumplist, "kdump ", 0, &cmdlist);

	c = add_cmd ("modules", class_files, kdumpmodules_command, 
		_("Load modules debuginfo from directory"), &kdumplist);
	set_cmd_completer (c, filename_completer);

	c = add_cmd ("ps", class_files, kdumpps_command, 
		_("Print ps info"), &kdumplist);

	set_cmd_completer (c, filename_completer);

#ifdef _DEBUG
	c = add_cmd ("kdumptest", class_files, kdumptest_file_command, _("\
Test command"), &kdumplist);
#endif
}

void 
_initialize_kdump (void)
{
	init_core_ops ();

	add_target_with_completer (&core_ops, filename_completer);
}
