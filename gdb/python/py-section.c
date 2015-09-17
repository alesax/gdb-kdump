/* Python interface to sections.

   Copyright (C) 2008-2013 Free Software Foundation, Inc.

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
#include "exceptions.h"
#include "frame.h"
#include "symtab.h"
#include "python-internal.h"
#include "objfiles.h"

typedef struct secpy_section_object {
  PyObject_HEAD
  asection *section;
  struct objfile *objfile;
  /* The GDB section structure this object is wrapping.  */
  /* A section object is associated with an objfile, so keep track with
     doubly-linked list, rooted in the objfile.  This lets us
     invalidate the underlying section when the objfile is
     deleted.  */
  struct secpy_section_object *prev;
  struct secpy_section_object *next;
} section_object;

/* Require a valid section.  All access to section_object->section should be
   gated by this call.  */
#define SYMPY_REQUIRE_VALID(section_obj, section)		\
  do {							\
    section = section_object_to_section (section_obj);	\
    if (section == NULL)					\
      {							\
	PyErr_SetString (PyExc_RuntimeError,		\
			 _("Section is invalid."));	\
	return NULL;					\
      }							\
  } while (0)

static const struct objfile_data *secpy_objfile_data_key;

static PyObject *
secpy_str (PyObject *self)
{
  PyObject *result;
  asection *section = NULL;

  SYMPY_REQUIRE_VALID (self, section);

  result = PyString_FromString (section->name);

  return result;
}

static PyObject *
secpy_get_flags (PyObject *self, void *closure)
{
  asection *section = NULL;

  SYMPY_REQUIRE_VALID (self, section);

  return PyInt_FromLong (section->flags);
}

static PyObject *
secpy_get_objfile (PyObject *self, void *closure)
{
  section_object *obj = (section_object *)self;

  if (! PyObject_TypeCheck (self, &section_object_type))
    return NULL;

  return objfile_to_objfile_object (obj->objfile);
}

static PyObject *
secpy_get_name (PyObject *self, void *closure)
{
  asection *section = NULL;

  SYMPY_REQUIRE_VALID (self, section);

  return PyString_FromString (section->name);
}

static PyObject *
secpy_get_id (PyObject *self, void *closure)
{
  asection *section = NULL;

  SYMPY_REQUIRE_VALID (self, section);

  return PyInt_FromLong (section->id);
}

#define secpy_return_string(self, val)		\
({						\
  asection *section = NULL;			\
  SYMPY_REQUIRE_VALID (self, section);		\
  PyString_FromString (val);		\
})

#define secpy_return_longlong(self, val)	\
({						\
  asection *section = NULL;			\
  SYMPY_REQUIRE_VALID (self, section);		\
  PyLong_FromUnsignedLongLong (val);	\
})

static PyObject *
secpy_get_vma (PyObject *self, void *closure)
{
  return secpy_return_longlong(self, section->vma);
}

static PyObject *
secpy_get_lma (PyObject *self, void *closure)
{
  return secpy_return_longlong(self, section->lma);
}

static PyObject *
secpy_get_size (PyObject *self, void *closure)
{
  return secpy_return_longlong(self, section->size);
}

static PyObject *
secpy_get_rawsize (PyObject *self, void *closure)
{
  return secpy_return_longlong(self, section->rawsize);
}

static PyObject *
secpy_get_compressed_size (PyObject *self, void *closure)
{
  return secpy_return_longlong(self, section->compressed_size);
}

static PyObject *
secpy_get_print_name (PyObject *self, void *closure)
{
  return secpy_str (self);
}

static PyObject *
secpy_is_compressed (PyObject *self, void *closure)
{
  asection *section = NULL;

  SYMPY_REQUIRE_VALID (self, section);

  return PyBool_FromLong (section->compress_status == 1);
}

/* Given a section, and a section_object that has previously been
   allocated and initialized, populate the section_object with the
   asection data.  Also, register the section_object life-cycle
   with the life-cycle of the object file associated with this
   section, if needed.  */
static void
set_section (section_object *obj, asection *section, struct objfile *objfile)
{
  obj->section = section;
  obj->prev = NULL;
  obj->objfile = objfile;
  obj->next = objfile_data (obj->objfile, secpy_objfile_data_key);

  if (obj->next)
    obj->next->prev = obj;

  set_objfile_data (obj->objfile, secpy_objfile_data_key, obj);
}

/* Create a new section object (gdb.Section) that encapsulates the struct
   section object from GDB.  */
PyObject *
section_to_section_object (asection *section, struct objfile *objfile)
{
  section_object *sec_obj;

  sec_obj = PyObject_New (section_object, &section_object_type);
  if (sec_obj) {
    set_section (sec_obj, section, objfile);
  }

  return (PyObject *) sec_obj;
}

/* Return the section that is wrapped by this section object.  */
asection *
section_object_to_section (PyObject *obj)
{
  if (! PyObject_TypeCheck (obj, &section_object_type))
    return NULL;
  return ((section_object *) obj)->section;
}

static void
secpy_dealloc (PyObject *obj)
{
  section_object *section_obj = (section_object *) obj;

  if (section_obj->prev)
    section_obj->prev->next = section_obj->next;
  else if (section_obj->objfile)
    {
      set_objfile_data (section_obj->objfile,
			secpy_objfile_data_key, section_obj->next);
    }
  if (section_obj->next)
    section_obj->next->prev = section_obj->prev;
  section_obj->section = NULL;
}

static PyObject *
secpy_is_valid (PyObject *self, PyObject *args)
{
  asection *section = NULL;

  section = section_object_to_section (self);
  if (section == NULL)
    Py_RETURN_FALSE;

  Py_RETURN_TRUE;
}

/* This function is called when an objfile is about to be freed.
   Invalidate the section as further actions on the section would result
   in bad data.  All access to obj->section should be gated by
   SYMPY_REQUIRE_VALID which will raise an exception on invalid
   sections.  */
static void
del_objfile_sections (struct objfile *objfile, void *datum)
{
  section_object *obj = datum;
  while (obj)
    {
      section_object *next = obj->next;

      obj->section = NULL;
      obj->next = NULL;
      obj->prev = NULL;

      obj = next;
    }
}

int
gdbpy_initialize_sections (void)
{
  if (PyType_Ready (&section_object_type) < 0)
    return -1;

  /* Register an objfile "free" callback so we can properly
     invalidate section when an object file that is about to be
     deleted.  */
  secpy_objfile_data_key
    = register_objfile_data_with_cleanup (NULL, del_objfile_sections);

  if (PyModule_AddIntConstant (gdb_module, "SEC_NO_FLAGS", SEC_NO_FLAGS) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_ALLOC", SEC_ALLOC) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_LOAD", SEC_LOAD) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_RELOC", SEC_RELOC) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_READONLY", SEC_READONLY) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_CODE", SEC_CODE) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_DATA", SEC_DATA) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_ROM", SEC_ROM) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_CONSTRUCTOR",
				  SEC_CONSTRUCTOR) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_HAS_CONTENTS",
				  SEC_HAS_CONTENTS) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_NEVER_LOAD",
				  SEC_NEVER_LOAD) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_THREAD_LOCAL",
				  SEC_THREAD_LOCAL) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_HAS_GOT_REF",
				  SEC_HAS_GOT_REF) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_IS_COMMON",
				  SEC_IS_COMMON) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_DEBUGGING",
				  SEC_DEBUGGING) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_IN_MEMORY",
				  SEC_IN_MEMORY) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_EXCLUDE", SEC_EXCLUDE) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_SORT_ENTRIES",
				  SEC_SORT_ENTRIES) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_LINK_ONCE",
				  SEC_LINK_ONCE) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_LINK_DUPLICATES",
				  SEC_LINK_DUPLICATES) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_LINK_DUPLICATES_DISCARD",
				  SEC_LINK_DUPLICATES_DISCARD) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_LINK_DUPLICATES_ONE_ONLY",
				  SEC_LINK_DUPLICATES_ONE_ONLY) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_LINK_DUPLICATES_SAME_SIZE",
				  SEC_LINK_DUPLICATES_SAME_SIZE) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_LINKER_CREATED",
				  SEC_LINKER_CREATED) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_KEEP", SEC_KEEP) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_SMALL_DATA",
				  SEC_SMALL_DATA) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_MERGE", SEC_MERGE) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_STRNGS", SEC_STRINGS) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_GROUP", SEC_GROUP) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_COFF_SHARED_LIBRARY",
				  SEC_COFF_SHARED_LIBRARY) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_ELF_REVERSE_COPY",
				  SEC_ELF_REVERSE_COPY) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_COFF_SHARED",
				  SEC_COFF_SHARED) < 0
      || PyModule_AddIntConstant (gdb_module, "SEC_COFF_NOREAD",
				  SEC_COFF_NOREAD) < 0)
    return -1;

  return gdb_pymodule_addobject (gdb_module, "Section",
				 (PyObject *) &section_object_type);
}



static PyGetSetDef section_object_getset[] = {
  { "flags", secpy_get_flags, NULL,
    "Flags of the section.", NULL },
  { "objfile", secpy_get_objfile, NULL,
    "Object file in which the section appears.", NULL },
  { "name", secpy_get_name, NULL,
    "Name of the section, as it appears in the source code.", NULL },
  { "size", secpy_get_size, NULL, "Size of the section.", NULL },
  { "compressed_size", secpy_get_compressed_size, NULL,
    "Compressed size of the section.", NULL },
  { "rawsize", secpy_get_rawsize, NULL,
    "Size of the section on disk.", NULL },
  { "id", secpy_get_id, NULL,
    "Sequence number of the section.", NULL },
  { "print_name", secpy_get_print_name, NULL,
    "Name of the section in a form suitable for output.\n\
This is either name or linkage_name, depending on whether the user asked GDB\n\
to display demangled or mangled names.", NULL },
  { "vma", secpy_get_vma, NULL,
    "Virtual memory address of the section at runtime." },
  { "lma", secpy_get_lma, NULL,
    "Load memory address of the section." },
  { "is_compressed", secpy_is_compressed, NULL,
    "True if the section is compressed." },
  { NULL }  /* Sentinel */
};

static PyMethodDef section_object_methods[] = {
  { "is_valid", secpy_is_valid, METH_NOARGS,
    "is_valid () -> Boolean.\n\
Return true if this section is valid, false if not." },
  {NULL}  /* Sentinel */
};

PyTypeObject section_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Section",		  /*tp_name*/
  sizeof (section_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  secpy_dealloc,		  /*tp_dealloc*/
  0,				  /*tp_print*/
  0,				  /*tp_getattr*/
  0,				  /*tp_setattr*/
  0,				  /*tp_compare*/
  0,				  /*tp_repr*/
  0,				  /*tp_as_number*/
  0,				  /*tp_as_sequence*/
  0,				  /*tp_as_mapping*/
  0,				  /*tp_hash */
  0,				  /*tp_call*/
  secpy_str,			  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,		  /*tp_flags*/
  "GDB section object",		  /*tp_doc */
  0,				  /*tp_traverse */
  0,				  /*tp_clear */
  0,				  /*tp_richcompare */
  0,				  /*tp_weaklistoffset */
  0,				  /*tp_iter */
  0,				  /*tp_iternext */
  section_object_methods,	  /*tp_methods */
  0,				  /*tp_members */
  section_object_getset		  /*tp_getset */
};
