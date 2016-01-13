#include "defs.h"
#include "python-internal.h"
#include "regcache.h"

extern PyTypeObject regcache_object_type;
extern PyTypeObject register_object_type;

typedef struct {
  PyObject_HEAD
  struct regcache *regcache;
} regcache_object;

typedef struct {
  PyObject_HEAD
  struct regcache *regcache;
  const char *name;
  int regnum;
} register_object;

/* Require a valid regcache.  All access to regcache_object->regcache should
   be gated by this call. */
#define RCPY_REQUIRE_VALID(regcache_obj, regcache)		\
   do {								\
     regcache = regcache_object_to_regcache (regcache_obj);	\
     if (regcache == NULL)					\
      {								\
	PyErr_SetString (PyExc_RuntimeError,			\
			 _("Regcache is invalid."));		\
	return NULL;						\
      }								\
    } while (0)

static void
set_regcache(regcache_object *obj, struct regcache *rc)
{
  obj->regcache = rc;
}

PyObject *
regcache_to_regcache_object (struct regcache *rc)
{
  regcache_object *regcache_obj;

  regcache_obj = PyObject_New (regcache_object, &regcache_object_type);
  if (regcache_obj)
    set_regcache (regcache_obj, rc);
  return (PyObject *) regcache_obj;
}

static regcache_object *
regcache_object_to_regcache (PyObject *obj)
{
  if (! PyObject_TypeCheck (obj, &regcache_object_type))
    return NULL;
  return ((regcache_object *) obj);
}

#define RCPY_REG_REQUIRE_VALID(register_obj, reg, ret)		\
  do {								\
    reg = register_object_to_register(register_obj);		\
    if (reg == NULL)						\
      {								\
	PyErr_SetString (PyExc_RuntimeError,			\
			 _("Regcache is invalid."));		\
	return ret;						\
      }								\
  } while(0)

static void
set_register(register_object *obj, struct regcache *rc,
	     const char *name, int regnum)
{
  obj->regcache = rc;
  obj->name = name;
  obj->regnum = regnum;
}

static PyObject *
register_to_register_object (struct regcache *rc, const char *name, int reg)
{
  register_object *register_obj;

  register_obj = PyObject_New (register_object, &register_object_type);
  if (register_obj)
    set_register (register_obj, rc, name, reg);
  return (PyObject *) register_obj;

}

static register_object *
register_object_to_register (PyObject *obj)
{
  if (! PyObject_TypeCheck (obj, &register_object_type))
    return NULL;
  return ((register_object *) obj);
}


static PyObject *
rcpy_get_registers (PyObject *self, void *closure)
{
  regcache_object *obj;
  struct gdbarch *gdbarch;
  int i, numregs;
  PyObject *d;

  RCPY_REQUIRE_VALID(self, obj);
  gdbarch = get_regcache_arch(obj->regcache);
  numregs = gdbarch_num_regs(gdbarch);

  d = PyDict_New();
  for (i = 0; i < numregs; i++)
    {
      struct register_object *robj;
      const char *name = gdbarch_register_name(gdbarch, i);
      PyObject *reg;

      if (!name || !*name)
	      continue;
      reg = register_to_register_object (obj->regcache, name, i);
      if (!reg) {
	Py_DECREF(d);
	return NULL;
      }
      if (PyDict_SetItemString(d, name, reg)) {
	Py_DECREF(reg);
	Py_DECREF(d);
	return NULL;
      }
    }

    return d;
}

static PyGetSetDef regcache_object_getset[] = {
  { "registers", rcpy_get_registers, NULL, "Dictionary of registers.", NULL },
  { NULL }  /* Sentinal */
};

PyTypeObject regcache_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.RegCache",		  /*tp_name*/
  sizeof(regcache_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  0,				  /*tp_delalloc*/
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
  0,				  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,  		  /*tp_flags*/
  "GDB regcache object",	  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  0,				  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  0,				  /* tp_iter */
  0,				  /* tp_iternext */
  0,	  			  /* tp_methods */
  0,				  /* tp_members */
  regcache_object_getset,	  /* tp_getset */
};

static PyObject *
register_get_name(PyObject *self, void *closure)
{
  register_object *obj;
  RCPY_REG_REQUIRE_VALID(self, obj, NULL);

  return PyString_FromString(obj->name);
}

static PyObject *
register_get_value(PyObject *self, void *closure)
{
  register_object *obj;
  struct value *value = NULL;

  RCPY_REG_REQUIRE_VALID(self, obj, NULL);

  TRY
    {
      /*
       * We don't want raw read since that expects to
       * read it from the core file
       */
      value = regcache_cooked_read_value(obj->regcache, obj->regnum);
    }
  CATCH (ex, RETURN_MASK_ERROR)
    {
      GDB_PY_HANDLE_EXCEPTION (ex);
    }
  END_CATCH

  return value_to_value_object(value);
}

static const char *
type_prefix (struct type *type)
{
  switch (TYPE_CODE(type))
    {
      case TYPE_CODE_UNION:
	return "union ";
      case TYPE_CODE_STRUCT:
	return "struct ";
      case TYPE_CODE_ENUM:
	return "enum ";
      }

    return "";
}

static int
register_set_value(PyObject *self, PyObject *value_obj, void *closure)
{
  register_object *obj;
  struct type *type, *vtype = NULL;
  struct value *value;
  struct gdbarch *gdbarch;

  RCPY_REG_REQUIRE_VALID(self, obj, -1);

  value = value_object_to_value(value_obj);
  if (value)
    vtype = value_type(value);

  gdbarch = get_regcache_arch(obj->regcache);
  type = register_type (gdbarch, obj->regnum);

  if (TYPE_CODE (type) == TYPE_CODE_PTR || is_integral_type (type))
    {
      unsigned long ul_value;
      if (PyLong_Check(value_obj))
	{
	  ul_value = PyLong_AsUnsignedLong (value_obj);
	  regcache_raw_supply (obj->regcache, obj->regnum, &ul_value);
	}
      else if (PyInt_Check (value_obj))
	{
	  ul_value = PyInt_AsUnsignedLongMask (value_obj);
	  regcache_raw_supply (obj->regcache, obj->regnum, &ul_value);
	}
      else if (vtype && (TYPE_CODE(vtype) == TYPE_CODE_PTR ||
			 is_integral_type (vtype)))
	{
	  regcache_raw_supply (obj->regcache, obj->regnum,
			       value_contents (value));
	}
      else
	{
	  PyErr_SetString (PyExc_TypeError,
			   "value must be pointer, int, long, or gdb.Value describing pointer or integral type");
	  return -1;
	}
    }
  else if (vtype && types_equal (type, vtype))
    {
      regcache_raw_supply (obj->regcache, obj->regnum, value_contents(value));
    }
  else
    {
      PyErr_Format (PyExc_TypeError,
		    "value type for register must be gdb.Value describing `%s%s'",
		    type_prefix (type), type_name_no_tag (type));
      return -1;
    }

  return 0;
}

static PyObject *
register_get_size(PyObject *self, void *closure)
{
  register_object *obj;
  struct gdbarch *gdbarch;
  RCPY_REG_REQUIRE_VALID(self, obj, NULL);
  gdbarch = get_regcache_arch(obj->regcache);
  return PyInt_FromLong(register_size(gdbarch, obj->regnum));
}

static PyObject *
register_get_regnum(PyObject *self, void *closure)
{
  register_object *obj;
  RCPY_REG_REQUIRE_VALID(self, obj, NULL);
  return PyInt_FromLong(obj->regnum);
}

static PyObject *
register_get_regtype(PyObject *self, void *closure)
{
  register_object *obj;
  struct gdbarch *gdbarch;
  struct type *type;
  RCPY_REG_REQUIRE_VALID(self, obj, NULL);

  gdbarch = get_regcache_arch(obj->regcache);
  type = register_type(gdbarch, obj->regnum);

  return type_to_type_object(type);
}

static PyGetSetDef register_object_getset[] = {
  { "name", register_get_name, NULL, "Register name.", NULL },
  { "value", register_get_value, register_set_value, "Register value.", NULL },
  { "size", register_get_size, NULL, "Register size.", NULL },
  { "regnum", register_get_regnum, NULL, "Register number.", NULL },
  { "type", register_get_regtype, NULL, "Register type.", NULL },
  { NULL }  /* Sentinal */
};

PyTypeObject register_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Register",		  /*tp_name*/
  sizeof(register_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  0,				  /*tp_delalloc*/
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
  0,				  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,		  /*tp_flags*/
  "GDB register object",	  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  0,				  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  0,				  /* tp_iter */
  0,				  /* tp_iternext */
  0,	  			  /* tp_methods */
  0,				  /* tp_members */
  register_object_getset,	  /* tp_getset */
};

int gdbpy_initialize_regcache (void)
{
    if (PyType_Ready (&register_object_type) < 0)
      return -1;
    if (PyType_Ready (&regcache_object_type) < 0)
      return -1;

    if (gdb_pymodule_addobject(gdb_module, "Register",
			       (PyObject *)&register_object_type))
      return -1;
    return gdb_pymodule_addobject(gdb_module, "Regcache",
				  (PyObject *)&regcache_object_type);
}
