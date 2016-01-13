#!/usr/bin/python

import kdump
#import crash.cache.tasks

symbol_cache = {}
charp = gdb.lookup_type('char').pointer()


def is_percpu_symbol(sym):
    return sym.section is not None and 'percpu' in sym.section.name

def get_value(name, domain=gdb.SYMBOL_VAR_DOMAIN):
    if name in symbol_cache:
        return symbol_cache[name]

    sym = gdb.lookup_global_symbol(name, domain=domain)
    if not sym:
        try:
            sym = gdb.lookup_symbol(name, domain=domain)[0]
        except Exception, e:
            print e

    if sym:
        val = sym.value()
        if is_percpu_symbol(sym):
            val = (val.cast(charp) + per_cpu_offset).cast(val.type)
        symbol_cache[name] = val
        return val

    return None

per_cpu_offset = get_value('__per_cpu_offset')
nr_cpus = per_cpu_offset.type.sizeof

def resolve_type(val):
    if isinstance(val, str):
        gdbtype = gdb.lookup_gdbtype(val)
    elif isinstance(val, gdb.Value):
        gdbtype = val.gdbtype
    else:
        gdbtype = val
    return gdbtype

def offsetof(val, member):
    gdbtype = resolve_type(val)
    if not isinstance(val, gdb.Type):
        raise TypeError("offsetof requires gdb.Type or a string/value that can be used to lookup a gdb.Type")

    return gdbtype[member].bitpos >> 3

def container_of(val, gdbtype, member):
    gdbtype = resolve_type(gdbtype)
    offset = offsetof(gdbtype, member)
    return (val.cast(charp) - offset).cast(gdbtype.pointer()).dereference()

list_head_type = gdb.lookup_type("struct list_head")
def list_for_each(list_head):
    if list_head.type == list_head_type.pointer():
        list_head = list_head.dereference()
    elif list_head.type != list_head_type:
        raise gdb.GdbError("Must be struct list_head not %s" % list_head.type)

    node = list_head['next'].dereference()
    while node.address != list_head.address:
        yield node.address
        node = node['next'].dereference()

def list_for_each_entry(list_head, gdbtype, member):
    for node in list_for_each(list_head):
        if node.type != list_head_type.pointer():
            raise TypeError("Type %s found. Expected struct list_head *." % node.type)
        yield container_of(node, gdbtype, member)
        
def per_cpu(symbol, cpu):
    if isinstance(symbol, str):
        symbol = gdb.lookup_global_symbol(symbol).value()
    elif isinstance(symbol, gdb.Symbol):
        symbol = symbol.value()
    else:
	raise TypeError("Must be string or gdb.Symbol")

    percpu_addr = symbol.address.cast(charp) + per_cpu_offset[cpu]
    return percpu_addr.cast(symbol.type.pointer()).dereference()

def in_exception_stack(sp):
    orig_ist = gdb.lookup_global_symbol("orig_ist")
    for cpu in range(0, 16):
        ist = per_cpu(orig_ist, cpu)
        num = ist['ist'].type.sizeof/ist['ist'][0].type.sizeof
        for index in range(0, num):
            end = ist['ist'][index]
            if sp >= end:
                continue
            if sp >= end - 4096:
                return end
    return 0

def active_tasks():
    runqueues = gdb.lookup_global_symbol("runqueues")
    tasks = []
    for cpu in range(0, 16):
        rq = per_cpu(runqueues, cpu)
        tasks.append(rq['curr'])

    return tasks

kdump.init_thread_list()
active = active_tasks()

rip = gdb.lookup_minimal_symbol("thread_return").value()
init_task = gdb.lookup_global_symbol("init_task")

task_list = init_task.value()['tasks']
ulong_type = gdb.lookup_type("unsigned long")
count = 0
pid1 = None

# Stack frame for __schedule should look like:
# mov    %rsp,%rbp
# push   %r15
# push   %r14
# push   %r13
# push   %r12
# push   %rbx
# sub    $0x28,%rsp
# ...
# pushfq
# push   %rbp
# That's 7 pushes and a sub of 5 longs, 12 slots
# call __switch_to
tasks = {} 
for task in list_for_each_entry(task_list, init_task.type, 'tasks'):
    rsp = task['thread']['sp'].cast(ulong_type.pointer())
    rbp = rsp.dereference().cast(ulong_type.pointer())
    rbx = (rbp - 1).dereference()
    r12 = (rbp - 2).dereference()
    r13 = (rbp - 3).dereference()
    r14 = (rbp - 4).dereference()
    r15 = (rbp - 5).dereference()

    # The two pushes that don't have CFI info
#    rsp += 2

    ex = in_exception_stack(rsp)
    if ex:
        print "EXCEPTION STACK: pid %d" % task['pid']

    thread = kdump.new_thread(task['pid'], task)
    thread.name = task['comm'].string()

    thread.regcache.registers['rsp'].value = rsp
    thread.regcache.registers['rbp'].value = rbp
    thread.regcache.registers['rip'].value = rip
    thread.regcache.registers['rbx'].value = rbx
    thread.regcache.registers['r12'].value = r12
    thread.regcache.registers['r13'].value = r13
    thread.regcache.registers['r14'].value = r14
    thread.regcache.registers['r15'].value = r15
    thread.regcache.registers['cs'] = 2*8
    thread.regcache.registers['ss'] = 3*8

#    if task['pid'] == 1:
#        for register, value in sorted(thread.regcache.registers.items()):
#            try:
#                print "%s = %lx" % (register, value.value)
#            except ValueError, e:
#                pass
#        pid1 = thread
#        break
    if task['pid'] == 8111:
        print task.address
    tasks[long(task.address)] = {
        'thread' : thread,
        'task' : task,
    }

#count = 0
#for task in active:
#    if long(task.address) in tasks:
#	    tasks[long(task.address)].thread.regcache.registers['rip'] = 0
#	    count +=1

print "Found %d active tasks" % count

kdump.set_executing(False)
kdump.reinit_frame_cache()
