/* Low level Alpha GNU/Linux interface, for GDB when running native.
   Copyright (C) 2005, 2006, 2007 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include "defs.h"
#include "target.h"
#include "linux-nat.h"

#include "alpha-tdep.h"

#include <sys/ptrace.h>
#include <alpha/ptrace.h>

#include <sys/procfs.h>
#include "gregset.h"

/* Given a pointer to either a gregset_t or fpregset_t, return a
   pointer to the first register.  */
#define ALPHA_REGSET_BASE(regsetp)  ((long *) (regsetp))

/* Given a pointer to a gregset_t, locate the UNIQUE value.  */
#define ALPHA_REGSET_UNIQUE(regsetp)  ((long *)(regsetp) + 32)

/* The address of UNIQUE for ptrace.  */
#define ALPHA_UNIQUE_PTRACE_ADDR 65


/*
 * See the comment in m68k-tdep.c regarding the utility of these functions.
 */

void
supply_gregset (gdb_gregset_t *gregsetp)
{
  long *regp = ALPHA_REGSET_BASE (gregsetp);
  void *unique = ALPHA_REGSET_UNIQUE (gregsetp);

  /* PC is in slot 32.  */
  alpha_supply_int_regs (-1, regp, regp + 31, unique);
}

void
fill_gregset (gdb_gregset_t *gregsetp, int regno)
{
  long *regp = ALPHA_REGSET_BASE (gregsetp);
  void *unique = ALPHA_REGSET_UNIQUE (gregsetp);

  /* PC is in slot 32.  */
  alpha_fill_int_regs (regno, regp, regp + 31, unique);
}

/*
 * Now we do the same thing for floating-point registers.
 * Again, see the comments in m68k-tdep.c.
 */

void
supply_fpregset (gdb_fpregset_t *fpregsetp)
{
  long *regp = ALPHA_REGSET_BASE (fpregsetp);

  /* FPCR is in slot 32.  */
  alpha_supply_fp_regs (-1, regp, regp + 31);
}

void
fill_fpregset (gdb_fpregset_t *fpregsetp, int regno)
{
  long *regp = ALPHA_REGSET_BASE (fpregsetp);

  /* FPCR is in slot 32.  */
  alpha_fill_fp_regs (regno, regp, regp + 31);
}


static CORE_ADDR
alpha_linux_register_u_offset (int regno)
{
  if (regno == PC_REGNUM)
    return PC;
  if (regno == ALPHA_UNIQUE_REGNUM)
    return ALPHA_UNIQUE_PTRACE_ADDR;
  if (regno < FP0_REGNUM)
    return GPR_BASE + regno;
  else
    return FPR_BASE + regno - FP0_REGNUM;
}

void _initialialize_alpha_linux_nat (void);

void
_initialize_alpha_linux_nat (void)
{
  linux_nat_add_target (linux_trad_target (alpha_linux_register_u_offset));
}
