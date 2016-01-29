#include "defs.h"
#include "gdbthread.h"
#include "gdbtypes.h"
#include "python-internal.h"

static void
release_task_struct (struct private_thread_info *priv)
{
  Py_DECREF((PyObject *)priv);
}

static PyObject *
kdump_new_thread(PyObject *self, PyObject *args)
{
  struct type *task_struct_type = lookup_struct("task_struct", NULL);
  struct type *type;
  struct value *value;
  PyObject *task_struct_object = NULL;
  pid_t lwp;
  ptid_t tt;
  struct thread_info *info;

  if (!PyArg_ParseTuple(args, "iO", &lwp, &task_struct_object))
    return NULL;

  if (!task_struct_type) {
    PyErr_SetString(PyExc_RuntimeError, "Couldn't retreive type information for task_struct.");
    return NULL;
  }

  value = value_object_to_value(task_struct_object);
  type = check_typedef(value_type(value));
  if (!type) {
    PyErr_SetString(PyExc_RuntimeError, "Couldn't resolve type for object.");
    return NULL;
  }

  if (TYPE_CODE(type) == TYPE_CODE_PTR) {
    task_struct_object = valpy_dereference(task_struct_object, NULL);
    gdb_assert(task_struct_object != NULL);

    value = value_object_to_value(task_struct_object);
    type = check_typedef(value_type(value));
  }

#if 0
  if (!value || !types_deeply_equal(type, task_struct_type)) {
      PyErr_SetString(PyExc_TypeError, "Task struct must be provided as a gdb.Value describing or pointing to a task_struct.");
      return NULL;
  }
#endif

  tt = ptid_build (1, lwp, 0);

  Py_INCREF(task_struct_object);
  info = add_thread_with_info(tt,
			      (struct private_thread_info *)task_struct_object);
  if (!info) {
    Py_DECREF(task_struct_object);
    Py_RETURN_NONE;
  }
  info->private_dtor = release_task_struct;
  return (PyObject *)create_thread_object(info);
}

extern PyTypeObject thread_object_type;
static PyObject *
kdump_task_address(PyObject *self, PyObject *args)
{
  PyObject *thread;
  thread_object *thread_obj;
  if (!PyArg_ParseTuple(args, "O!", &thread, &thread_object_type))
    return NULL;

  thread_obj = (thread_object *)thread;
  if (!thread_obj->thread) {
          PyErr_SetString (PyExc_RuntimeError,
	                           _("Thread no longer exists."));
	  return NULL;
  }
  return PyLong_FromVoidPtr(thread_obj->thread->priv);
}

static PyObject *
kdump_set_executing(PyObject *self, PyObject *args)
{
  pid_t lwp;
  PyObject *executing;
  struct thread_info *info;
  if (!PyArg_ParseTuple(args, "O", &executing))
    return NULL;

  set_executing(minus_one_ptid, PyObject_IsTrue(executing));
  Py_RETURN_NONE;
}

static PyObject *
kdump_reinit_frame_cache(PyObject *self, PyObject *args)
{
  reinit_frame_cache();
  Py_RETURN_NONE;
}

PyMethodDef python_KdumpMethods[] =
{
  { "new_thread", kdump_new_thread, METH_VARARGS,
    "new_thread () -> gdb.InferiorThread.\n\
Return newly created inferior thread." },
  { "set_executing", kdump_set_executing, METH_VARARGS,
    "set_executing () -> None." },
  { "reinit_frame_cache", kdump_reinit_frame_cache, METH_NOARGS,
    "Reinitialize the frame cache." },
  { "task_address", kdump_task_address, METH_VARARGS,
    "Get task address for thread () -> Long." },
  { NULL }
};

PyObject *kdump_module;

int
kdump_init_module(void)
{
  kdump_module = Py_InitModule ("_kdump", python_KdumpMethods);
  if (kdump_module == NULL)
	  return -1;
  init_thread_list();
  return 0;
}

#if 0
PyTypeObject kdump_target_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  "kdump.Target",		  /*tp_name*/
  sizeof (kdump_target_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  kdump_target_dealloc,		  /*tp_dealloc*/
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
  "Kdump target object",	  /*tp_doc */
  0,				  /*tp_traverse */
  0,				  /*tp_clear */
  0,				  /*tp_richcompare */
  0,				  /*tp_weaklistoffset */
  0,				  /*tp_iter */
  0,				  /*tp_iternext */
  kdump_target_object_methods	  /*tp_methods */
};
#endif
