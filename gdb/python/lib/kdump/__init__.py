#!/usr/bin/python

import _kdump
import gdb

task_struct_type = gdb.lookup_global_symbol("init_task").type

def new_thread(pid, task_struct):
    if task_struct.type != task_struct_type and \
       task_struct.type != task_struct_type.pointer():
        raise TypeError("Task must be specified with `%s' not `%s'" % \
                        (task_struct_type, task_struct.type))
    return _kdump.new_thread(pid, task_struct)


def set_executing(executing):
    return _kdump.set_executing(executing)

def reinit_frame_cache():
    _kdump.reinit_frame_cache()

def init_thread_list():
    _kdump.init_thread_list()
