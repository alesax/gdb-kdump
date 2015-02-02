/* Core dump and executable file functions below target vector, for GDB.

 Copyright (C) 1986-2014 Free Software Foundation, Inc.

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
#include "kdumpfile.h"
#include "kdump_types.h"

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

static struct target_ops core_ops;

static kdump_ctx *dump_ctx = NULL;

struct gdbarch *kdump_gdbarch = NULL;

struct target_ops *kdump_target = NULL;

static void init_core_ops (void);

void _initialize_kdump (void);

static void core_close (struct target_ops *self);

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

	for (i = 0; i < nc; i++) {
		for (r = 0; ; r++) {
			if (kdump_read_reg(dump_ctx, i, r, &reg)) break;
			fprintf(stdout, "CPU % 2d,REG%02d=%llx\n", i, r, (long long unsigned int)reg);
		}

	}

	kdump_types_init(flags);
	return (0);
}

#define SYMBOL(var,name) do { var = lookup_symbol(name, NULL, VAR_DOMAIN, NULL); if (! var) { fprintf(stderr, "Cannot lookup_symbol(" name ")\n"); goto error; } } while(0)

static int init_values(void);
static int init_values(void)
{
	struct symbol *s;
	char *b = NULL, *init_task = NULL, *task = NULL;
	offset off, off_task, rsp, rip;
	offset tasks;
	offset stack;
	int state;
	int i;
	int hashsize;

	SYMBOL(s, "init_task");
	init_task = kdump_type_alloc((struct kdump_type*)&kt_task_struct, SYMBOL_VALUE_ADDRESS(s), 0, NULL);

	tasks = kt_ptr_value(init_task + kt_task_struct.tasks);

	i = 0;
	off = 0;

	kt_list_head_for_each(0, tasks, init_task + kt_task_struct.tasks, off) {
		struct thread_info *info;
		struct inferior *in;
		int pid;
		ptid_t tt;
		struct regcache *rc;
		long long val;

		off_task = off - kt_task_struct.tasks;
		task = kdump_type_alloc((struct kdump_type*)&kt_task_struct, off_task, 0, task);

		state = kt_int_value(task + kt_task_struct.state);
		pid = kt_int_value(task + kt_task_struct.pid);
		stack = kt_ptr_value(task + kt_task_struct.stack);
		rsp = kt_ptr_value(task + kt_task_struct.thread + kt_thread_struct.sp);
		b = kdump_type_alloc((struct kdump_type*)&kt_voidp, rsp, 0, b);
		rip = kt_ptr_value(b);
#ifdef _DEBUG
		fprintf(stdout, "TASK %llx,%llx,%llx,rip=%llx,pid=%d,state=%d,name=%s\n", off_task, stack, rsp, rip, pid, state, task + kt_task_struct.comm);
#endif
		fprintf(stdout, "TASK %llx,%llx,%llx,rip=%llx,pid=%d,state=%d,name=%s\n", off_task, stack, rsp, rip, pid, state, task + kt_task_struct.comm);

		if (pid == 0) continue;
		in = current_inferior();
		tt = ptid_build (1, pid, 0);
		inferior_appeared (in, 1);
		add_thread(tt);
		inferior_ptid = tt;
		info = find_thread_ptid (tt);
		info->name = strdup(task + kt_task_struct.comm);
			
		val = 0;

		rc = get_thread_regcache (tt);

		for (i = 0; i < 55; i++) {
			val = 0x12400 + i;
			val = __bswap_64(val);
			regcache_raw_supply(rc, i, &val);
		}
		val = __bswap_64(rip);
		regcache_raw_supply(rc, 1, &val);
		/* 
		 * The task is not running - e.g. crash would show it's stuck in schedule()
		 * Yet schedule() is not on it's stack.
		 *
		 */
		if (state != 0) {
			long long regs[6];

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

			//rip = 0xffffffff8145ff0b;
			b = kdump_type_alloc((struct kdump_type*)&kt_voidp, rsp, 0, b);
			rip = kt_ptr_value(b);
			rsp += 8;
		}
		val = __bswap_64(rip); 
		regcache_raw_supply(rc, 7, &val);
		regcache_write_pc(rc, rip);
		val = __bswap_64(rsp);
		regcache_raw_supply(rc, 17, &val);
	}

error:
	if (b) free(b);
	if (init_task) free(init_task);

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
	if (!arg)
	  {
	    if (core_bfd)
	error (_("No kdump file specified.  (Use `detach' "
		 "to stop debugging a core file.)"));
	    else
	error (_("No kdump file specified."));
	  }

	printf("OPEN KDUMP TRACEUR!\n");
	filename = tilde_expand (arg);
	if (!IS_ABSOLUTE_PATH (filename))
	  {
	    temp = concat (current_directory, "/",
			   filename, (char *) NULL);
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
		error(_("Cannot kdump_vtop_init()\n"));
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
		} *a, archlist[] = {
			{"x86_64", "i386:x86-64", 0},
			{"s390x",  "s390:64-bit", 1},
			{NULL}
		};

		archname = kdump_arch_name(dump_ctx);
		if (! archname) {
			error(_("The architecture could not be identified"));
			return;
		}
		for (a = archlist; a->kdident && strcmp(a->kdident, archname); a++);

		if (! a->kdident) {
			error(_("Architecture %s is not yet supported by gdb-kdump\n"), archname);
			return;
		}

		gdbarch_info_init(&gai);
		ait = bfd_scan_arch (a->gdbident);
		if (! ait) {
			error(_("Architecture %s not supported in gdb\n"), a->gdbident);
			return;
		}
		gai.bfd_arch_info = ait;
		garch = gdbarch_find_by_info(gai);
		kdump_gdbarch = garch; 
#ifdef _DEBUG
		fprintf(stderr, "arch=%s,ait=%p,garch=%p\n", selected_architecture_name(), ait, garch);
#endif
		init_thread_list();
		inf = current_inferior();
		
		if (init_types(a->flags)) {
			fprintf(stderr, "Cannot init types!\n");
		}
		if (init_values()) {
			fprintf(stderr, "Cannot init values!\n");
		}
		reinit_frame_cache();
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
/* FIXME: we do have to implement full scale
 * virtual memory mapping! 
 * if (addr > 0xffffffffa0000000) ...
 */
	if (addr > 0xffffffff80000000)
		return(addr&0xfffffff);
	if (addr > 0xffff880000000000)
		return(addr&0xffffffffff);
	else return(addr);
	
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
			  error(_("Cannot read %lu bytes from %llu (%lld)!"), (size_t)len, (long long)offset, (long long)r);
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

static int
ignore (struct target_ops *ops, struct gdbarch *gdbarch,
	struct bp_target_info *bp_tgt)
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

	    result = gdbarch_core_read_description (kdump_gdbarch, 
						    target, core_bfd);
	    if (result != NULL)
	return result;
	  }

	return target->beneath->to_read_description (target->beneath);
}
static int
core_has_memory (struct target_ops *ops)
{
	return 1;
}

static int
core_has_stack (struct target_ops *ops)
{
	return 1;
}

static int
core_has_registers (struct target_ops *ops)
{
	return 1;
}



void
kdump_file_command (char *filename, int from_tty);

void
kdump_file_command (char *filename, int from_tty)
{
	dont_repeat ();		/* Either way, seems bogus.  */

	gdb_assert (kdump_target != NULL);

	if (!filename)
	  (kdump_target->to_detach) (kdump_target, filename, from_tty);
	else
	  (kdump_target->to_open) (filename, from_tty);
}


static void
init_core_ops (void)
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

	if (kdump_target)
	  internal_error (__FILE__, __LINE__, 
			  _("init_kdump_ops: core target already exists (\"%s\")."),
			  kdump_target->to_longname);
	kdump_target = &core_ops;

	c = add_cmd ("kdump-file", class_files, kdump_file_command, _("\
Use FILE as kdump for examining memory and registers.\n\
No arg means have no core file.  This command has been superseded by the\n\
`target core' and `detach' commands."), &cmdlist);

	set_cmd_completer (c, filename_completer);


}

void
_initialize_kdump (void)
{
	init_core_ops ();

	add_target_with_completer (&core_ops, filename_completer);
}
