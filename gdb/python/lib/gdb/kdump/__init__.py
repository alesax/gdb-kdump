import gdb

def list_head(obj, field, typ=None):
	if typ == None:
		typ = obj.type
	nextaddr = long(obj[field.name]["next"])
	addr = long(long(obj.address)+(field.bitpos>>3))
	
	yield obj

	while not addr == nextaddr:
		nv = gdb.Value(long(nextaddr-(field.bitpos>>3))).cast(typ.pointer()).dereference()
		nextaddr = long(nv[field.name]["next"])
		yield nv

		"""
import gdb.kdump
sz=gdb.lookup_symbol("init_task")[0]
g=gdb.kdump.list_head(sz.value(), sz.value().type["tasks"])
"""
