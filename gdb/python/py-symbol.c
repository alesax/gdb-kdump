/* Python interface to symbols.

   Copyright (C) 2008-2015 Free Software Foundation, Inc.

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
#include "block.h"
#include "frame.h"
#include "symtab.h"
#include "python-internal.h"
#include "objfiles.h"

typedef struct sympy_symbol_object {
  PyObject_HEAD
  /* The GDB symbol structure this object is wrapping.  */
  struct symbol *symbol;
  /* A symbol object is associated with an objfile, so keep track with
     doubly-linked list, rooted in the objfile.  This lets us
     invalidate the underlying struct symbol when the objfile is
     deleted.  */
  struct sympy_symbol_object *prev;
  struct sympy_symbol_object *next;
  int field_of_type;
} symbol_object;

/* Require a valid symbol.  All access to symbol_object->symbol should be
   gated by this call.  */
#define SYMPY_REQUIRE_VALID(symbol_obj, symbol)		\
  do {							\
    symbol = symbol_object_to_symbol (symbol_obj);	\
    if (symbol == NULL)					\
      {							\
	PyErr_SetString (PyExc_RuntimeError,		\
			 _("Symbol is invalid."));	\
	return NULL;					\
      }							\
  } while (0)

static const struct objfile_data *sympy_objfile_data_key;

static PyObject *
sympy_str (PyObject *self)
{
  PyObject *result;
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  result = PyString_FromString (SYMBOL_PRINT_NAME (symbol));

  return result;
}

static PyObject *
sympy_get_type (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  if (SYMBOL_TYPE (symbol) == NULL)
    {
      Py_INCREF (Py_None);
      return Py_None;
    }

  return type_to_type_object (SYMBOL_TYPE (symbol));
}

static PyObject *
sympy_get_symtab (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  if (!SYMBOL_OBJFILE_OWNED (symbol))
    Py_RETURN_NONE;

  return symtab_to_symtab_object (symbol_symtab (symbol));
}

static PyObject *
sympy_get_name (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  return PyString_FromString (SYMBOL_NATURAL_NAME (symbol));
}

static PyObject *
sympy_get_linkage_name (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  return PyString_FromString (SYMBOL_LINKAGE_NAME (symbol));
}

static PyObject *
sympy_get_print_name (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  return sympy_str (self);
}

static PyObject *
sympy_get_addr_class (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  return PyInt_FromLong (SYMBOL_CLASS (symbol));
}

static PyObject *
sympy_is_argument (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  return PyBool_FromLong (SYMBOL_IS_ARGUMENT (symbol));
}

static PyObject *
sympy_is_constant (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;
  enum address_class theclass;

  SYMPY_REQUIRE_VALID (self, symbol);

  theclass = SYMBOL_CLASS (symbol);

  return PyBool_FromLong (theclass == LOC_CONST || theclass == LOC_CONST_BYTES);
}

static PyObject *
sympy_is_function (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;
  enum address_class theclass;

  SYMPY_REQUIRE_VALID (self, symbol);

  theclass = SYMBOL_CLASS (symbol);

  return PyBool_FromLong (theclass == LOC_BLOCK);
}

static PyObject *
sympy_is_variable (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;
  enum address_class theclass;

  SYMPY_REQUIRE_VALID (self, symbol);

  theclass = SYMBOL_CLASS (symbol);

  return PyBool_FromLong (!SYMBOL_IS_ARGUMENT (symbol)
			  && (theclass == LOC_LOCAL || theclass == LOC_REGISTER
			      || theclass == LOC_STATIC || theclass == LOC_COMPUTED
			      || theclass == LOC_OPTIMIZED_OUT));
}

/* Implementation of gdb.Symbol.needs_frame -> Boolean.
   Returns true iff the symbol needs a frame for evaluation.  */

static PyObject *
sympy_needs_frame (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;
  int result = 0;

  SYMPY_REQUIRE_VALID (self, symbol);

  TRY
    {
      result = symbol_read_needs_frame (symbol);
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }
  END_CATCH

  if (result)
    Py_RETURN_TRUE;
  Py_RETURN_FALSE;
}

/* Implementation of gdb.Symbol.line -> int.
   Returns the line number at which the symbol was defined.  */

static PyObject *
sympy_line (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;

  SYMPY_REQUIRE_VALID (self, symbol);

  return PyInt_FromLong (SYMBOL_LINE (symbol));
}

/* Implementation of gdb.Symbol.is_valid (self) -> Boolean.
   Returns True if this Symbol still exists in GDB.  */

static PyObject *
sympy_is_valid (PyObject *self, PyObject *args)
{
  struct symbol *symbol = NULL;

  symbol = symbol_object_to_symbol (self);
  if (symbol == NULL)
    Py_RETURN_FALSE;

  Py_RETURN_TRUE;
}

static PyObject *
sympy_section (PyObject *self, void *closure)
{
  struct symbol *symbol = NULL;
  PyObject *section_obj;
  struct obj_section *section;

  SYMPY_REQUIRE_VALID (self, symbol);

  section = SYMBOL_OBJ_SECTION(symbol_objfile(symbol), symbol);

  if (section) {
    section_obj = section_to_section_object(section->the_bfd_section,
                                            symbol_objfile(symbol));
    if (section_obj)
      return section_obj;
  }

  Py_INCREF (Py_None);
  return Py_None;
}

/* Implementation of gdb.Symbol.value (self[, frame]) -> gdb.Value.  Returns
   the value of the symbol, or an error in various circumstances.  */

static PyObject *
sympy_value (PyObject *self, PyObject *args)
{
  struct symbol *symbol = NULL;
  struct frame_info *frame_info = NULL;
  PyObject *frame_obj = NULL;
  struct value *value = NULL;

  if (!PyArg_ParseTuple (args, "|O", &frame_obj))
    return NULL;

  if (frame_obj != NULL && !PyObject_TypeCheck (frame_obj, &frame_object_type))
    {
      PyErr_SetString (PyExc_TypeError, "argument is not a frame");
      return NULL;
    }

  SYMPY_REQUIRE_VALID (self, symbol);
  if (SYMBOL_CLASS (symbol) == LOC_TYPEDEF)
    {
      PyErr_SetString (PyExc_TypeError, "cannot get the value of a typedef");
      return NULL;
    }

  TRY
    {
      if (frame_obj != NULL)
	{
	  frame_info = frame_object_to_frame_info (frame_obj);
	  if (frame_info == NULL)
	    error (_("invalid frame"));
	}

      if (symbol_read_needs_frame (symbol) && frame_info == NULL)
	error (_("symbol requires a frame to compute its value"));

      value = read_var_value (symbol, frame_info);
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }
  END_CATCH

  return value_to_value_object (value);
}

/* Given a symbol, and a symbol_object that has previously been
   allocated and initialized, populate the symbol_object with the
   struct symbol data.  Also, register the symbol_object life-cycle
   with the life-cycle of the object file associated with this
   symbol, if needed.  */
static void
set_symbol (symbol_object *obj, struct symbol *symbol)
{
  obj->symbol = symbol;
  obj->prev = NULL;
  if (SYMBOL_OBJFILE_OWNED (symbol)
      && symbol_symtab (symbol) != NULL)
    {
      struct objfile *objfile = symbol_objfile (symbol);

      obj->next = objfile_data (objfile, sympy_objfile_data_key);
      if (obj->next)
	obj->next->prev = obj;
      set_objfile_data (objfile, sympy_objfile_data_key, obj);
    }
  else
    obj->next = NULL;
}

/* Create a new symbol object (gdb.Symbol) that encapsulates the struct
   symbol object from GDB.  */
PyObject *
symbol_to_symbol_object (struct symbol *sym)
{
  symbol_object *sym_obj;

  sym_obj = PyObject_New (symbol_object, &symbol_object_type);
  if (sym_obj)
    set_symbol (sym_obj, sym);

  return (PyObject *) sym_obj;
}

/* Return the symbol that is wrapped by this symbol object.  */
struct symbol *
symbol_object_to_symbol (PyObject *obj)
{
  if (! PyObject_TypeCheck (obj, &symbol_object_type))
    return NULL;
  return ((symbol_object *) obj)->symbol;
}

static void
sympy_dealloc (PyObject *obj)
{
  symbol_object *sym_obj = (symbol_object *) obj;

  if (sym_obj->prev)
    sym_obj->prev->next = sym_obj->next;
  else if (sym_obj->symbol != NULL
	   && SYMBOL_OBJFILE_OWNED (sym_obj->symbol)
	   && symbol_symtab (sym_obj->symbol) != NULL)
    {
      set_objfile_data (symbol_objfile (sym_obj->symbol),
			sympy_objfile_data_key, sym_obj->next);
    }
  if (sym_obj->next)
    sym_obj->next->prev = sym_obj->prev;
  sym_obj->symbol = NULL;
}


static int
pysym_lookup_symbol(symbol_object *sym_obj, const char *name, int domain,
		    PyObject *block_obj)
{
  const struct block *block = NULL;
  struct field_of_this_result is_a_field_of_this;
  struct symbol *symbol = NULL;

  if (block_obj)
    block = block_object_to_block (block_obj);

  if (!block)
    {
      struct frame_info *selected_frame;

      TRY
	{
	  if (symbol && symbol_read_needs_frame(symbol)) {
	      selected_frame = get_selected_frame (_("No frame selected."));
	      block = get_frame_block (selected_frame, NULL);
	    }
	}
      CATCH (except, RETURN_MASK_ALL)
       {
         GDB_PY_SET_HANDLE_EXCEPTION (except);
       }
      END_CATCH
    }

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      symbol = lookup_symbol (name, block, domain, &is_a_field_of_this);
    }
  GDB_PY_SET_HANDLE_EXCEPTION (except);

  if (symbol) {
    set_symbol (sym_obj, symbol);
    sym_obj->field_of_type = (is_a_field_of_this.type != NULL);
  }
  return 0;
}

/* Implementation of
   gdb.lookup_symbol (name [, block] [, domain]) -> (symbol, is_field_of_this)
   A tuple with 2 elements is always returned.  The first is the symbol
   object or None, the second is a boolean with the value of
   is_a_field_of_this (see comment in lookup_symbol_in_language).  */

PyObject *
gdbpy_lookup_symbol (PyObject *self, PyObject *args, PyObject *kw)
{
  int domain = VAR_DOMAIN;
  struct field_of_this_result is_a_field_of_this;
  const char *name;
  static char *keywords[] = { "name", "block", "domain", NULL };
  struct symbol *symbol = NULL;
  PyObject *block_obj = NULL, *ret_tuple, *sym_pyobj = NULL, *bool_obj;
  const struct block *block = NULL;
  symbol_object *sym_obj = NULL;

  if (! PyArg_ParseTupleAndKeywords (args, kw, "s|O!i", keywords, &name,
				     &block_object_type, &block_obj, &domain))
    return NULL;

  sym_obj = PyObject_New (symbol_object, &symbol_object_type);
  if (!sym_obj)
    return NULL;

  sym_pyobj = (PyObject *)sym_obj;

  ret_tuple = PyTuple_New (2);
  if (!ret_tuple)
    {
      Py_DECREF (sym_pyobj);
      return NULL;
    }

  if (pysym_lookup_symbol(sym_obj, name, domain, block_obj) < 0)
    {
      Py_DECREF (sym_pyobj);
      Py_DECREF (ret_tuple);
      return NULL;
    }

  if (!sym_obj->symbol)
    {
      Py_DECREF (sym_pyobj);
      Py_INCREF (Py_None);
      sym_pyobj = Py_None;
      sym_obj = NULL;
    }
  PyTuple_SET_ITEM (ret_tuple, 0, sym_pyobj);

  bool_obj = (sym_obj && sym_obj->field_of_type) ? Py_True : Py_False;
  Py_INCREF(bool_obj);
  PyTuple_SET_ITEM(ret_tuple, 1, bool_obj);

  return ret_tuple;
}

static int
pysym_lookup_symbol_global(symbol_object *sym_obj, const char *name,
			   int domain, PyObject *block_obj)
{
  const struct block *block = NULL;
  struct symbol *symbol = NULL;

  if (block_obj)
    block = block_object_to_block (block_obj);

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      symbol = lookup_symbol_global (name, block, domain);
    }
  GDB_PY_SET_HANDLE_EXCEPTION (except);

  if (symbol)
    set_symbol(sym_obj, symbol);

  return 0;
}

/* Implementation of
   gdb.lookup_global_symbol (name [, domain]) -> symbol or None.  */

PyObject *
gdbpy_lookup_global_symbol (PyObject *self, PyObject *args, PyObject *kw)
{
  int domain = VAR_DOMAIN;
  const char *name;
  static char *keywords[] = { "name", "domain", NULL };
  struct symbol *symbol = NULL;
  symbol_object *sym_obj;

  if (! PyArg_ParseTupleAndKeywords (args, kw, "s|i", keywords, &name,
				     &domain))
    return NULL;

  sym_obj = PyObject_New (symbol_object, &symbol_object_type);
  if (!sym_obj)
    return NULL;

  if (pysym_lookup_symbol_global(sym_obj, name, domain, NULL) < 0)
    {
      Py_DECREF(sym_obj);
      return NULL;
    }

  if (!sym_obj->symbol)
    {
      Py_DECREF (sym_obj);
      Py_INCREF (Py_None);
      return Py_None;
    }

  return (PyObject *)sym_obj;
}

/* This function is called when an objfile is about to be freed.
   Invalidate the symbol as further actions on the symbol would result
   in bad data.  All access to obj->symbol should be gated by
   SYMPY_REQUIRE_VALID which will raise an exception on invalid
   symbols.  */
static void
del_objfile_symbols (struct objfile *objfile, void *datum)
{
  symbol_object *obj = datum;
  while (obj)
    {
      symbol_object *next = obj->next;

      obj->symbol = NULL;
      obj->next = NULL;
      obj->prev = NULL;

      obj = next;
    }
}

int
gdbpy_initialize_symbols (void)
{
  if (PyType_Ready (&symbol_object_type) < 0)
    return -1;

  /* Register an objfile "free" callback so we can properly
     invalidate symbol when an object file that is about to be
     deleted.  */
  sympy_objfile_data_key
    = register_objfile_data_with_cleanup (NULL, del_objfile_symbols);

  if (PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_UNDEF", LOC_UNDEF) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_CONST",
				  LOC_CONST) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_STATIC",
				  LOC_STATIC) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_REGISTER",
				  LOC_REGISTER) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_ARG",
				  LOC_ARG) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_REF_ARG",
				  LOC_REF_ARG) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_LOCAL",
				  LOC_LOCAL) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_TYPEDEF",
				  LOC_TYPEDEF) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_LABEL",
				  LOC_LABEL) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_BLOCK",
				  LOC_BLOCK) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_CONST_BYTES",
				  LOC_CONST_BYTES) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_UNRESOLVED",
				  LOC_UNRESOLVED) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_OPTIMIZED_OUT",
				  LOC_OPTIMIZED_OUT) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_COMPUTED",
				  LOC_COMPUTED) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LOC_REGPARM_ADDR",
				  LOC_REGPARM_ADDR) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_UNDEF_DOMAIN",
				  UNDEF_DOMAIN) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_VAR_DOMAIN",
				  VAR_DOMAIN) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_STRUCT_DOMAIN",
				  STRUCT_DOMAIN) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_LABEL_DOMAIN",
				  LABEL_DOMAIN) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_VARIABLES_DOMAIN",
				  VARIABLES_DOMAIN) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_FUNCTIONS_DOMAIN",
				  FUNCTIONS_DOMAIN) < 0
      || PyModule_AddIntConstant (gdb_module, "SYMBOL_TYPES_DOMAIN",
				  TYPES_DOMAIN) < 0)
    return -1;

  return gdb_pymodule_addobject (gdb_module, "Symbol",
				 (PyObject *) &symbol_object_type);
}

static PyObject *
symbol_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  symbol_object *self = (symbol_object *)type->tp_alloc(type, 0);
  if (self)
    {
      self->symbol = NULL;
      self->prev = NULL;
      self->next = NULL;
      self->field_of_type = 0;
    }

  return self;
}

static int
symbol_object_init(PyObject *self, PyObject *args, PyObject *kwds)
{
  int domain = VAR_DOMAIN;
  const char *name;
  PyObject *block_obj = NULL, *bool_obj = NULL;
  int global = 1;
  symbol_object *sym_obj = (symbol_object *)self;
  int ret;

  static char *keywords[] = {"name", "global", "domain", "block", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O!iO!", keywords, &name,
				   &PyBool_Type, &bool_obj, &block_object_type,
				   &block_obj, &domain))
    return -1;

  if (bool_obj)
    global = (bool_obj == Py_True);

  if (global)
    ret = pysym_lookup_symbol_global(sym_obj, name, domain, block_obj);
  else
    ret = pysym_lookup_symbol(sym_obj, name, domain, block_obj);

  if (ret < 0 || !sym_obj->symbol)
    return -1;

  return 0;
}



static PyGetSetDef symbol_object_getset[] = {
  { "type", sympy_get_type, NULL,
    "Type of the symbol.", NULL },
  { "symtab", sympy_get_symtab, NULL,
    "Symbol table in which the symbol appears.", NULL },
  { "name", sympy_get_name, NULL,
    "Name of the symbol, as it appears in the source code.", NULL },
  { "linkage_name", sympy_get_linkage_name, NULL,
    "Name of the symbol, as used by the linker (i.e., may be mangled).",
    NULL },
  { "print_name", sympy_get_print_name, NULL,
    "Name of the symbol in a form suitable for output.\n\
This is either name or linkage_name, depending on whether the user asked GDB\n\
to display demangled or mangled names.", NULL },
  { "addr_class", sympy_get_addr_class, NULL, "Address class of the symbol." },
  { "is_argument", sympy_is_argument, NULL,
    "True if the symbol is an argument of a function." },
  { "is_constant", sympy_is_constant, NULL,
    "True if the symbol is a constant." },
  { "is_function", sympy_is_function, NULL,
    "True if the symbol is a function or method." },
  { "is_variable", sympy_is_variable, NULL,
    "True if the symbol is a variable." },
  { "needs_frame", sympy_needs_frame, NULL,
    "True if the symbol requires a frame for evaluation." },
  { "line", sympy_line, NULL,
    "The source line number at which the symbol was defined." },
  { "section", sympy_section, NULL,
    "Section of executable where symbol resides." },
  { NULL }  /* Sentinel */
};

static PyMethodDef symbol_object_methods[] = {
  { "is_valid", sympy_is_valid, METH_NOARGS,
    "is_valid () -> Boolean.\n\
Return true if this symbol is valid, false if not." },
  { "value", sympy_value, METH_VARARGS,
    "value ([frame]) -> gdb.Value\n\
Return the value of the symbol." },
  {NULL}  /* Sentinel */
};

PyTypeObject symbol_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  .tp_name = "gdb.Symbol",
  .tp_basicsize = sizeof (symbol_object),
  .tp_dealloc = sympy_dealloc,
  .tp_str = sympy_str,
  .tp_flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
  .tp_doc = "GDB symbol object",
  .tp_methods = symbol_object_methods,
  .tp_getset = symbol_object_getset,
  .tp_init = symbol_object_init,
  .tp_new = symbol_object_new,
};
