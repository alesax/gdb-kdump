#!/bin/sh

cat << 'EOF'
$! Set the def dir to proper place for use in batch. Works for interactive to.
$flnm = f$enviroment("PROCEDURE")     ! get current procedure name
$set default 'f$parse(flnm,,,"DEVICE")''f$parse(flnm,,,"DIRECTORY")'
$!
$!	Command file to build a GNU assembler on VMS
$!
$!	If you are using a version of GCC that supports global constants
$!	you should remove the define="const=" from the gcc lines.
$!
$!	Caution:  Versions 1.38.1 and earlier had a bug in the handling of
$!	some static constants. If you are using such a version of the
$!	assembler, and you wish to compile without the "const=" hack,
$!	you should first build this version *with* the "const="
$!	definition, and then use that assembler to rebuild it without the
$!	"const=" definition.  Failure to do this will result in an assembler
$!	that will mung floating point constants.
$!
$!	Note: The version of gas shipped on the GCC VMS tapes has been patched
$!	to fix the above mentioned bug.
$!
$ write sys$output "If this assembler is going to be used with GCC 1.n, you"
$ write sys$Output "need to modify the driver to supply the -1 switch to gas."
$ write sys$output "This is required because of a small change in how global"
$ write sys$Output "constant variables are handled.  Failure to include this"
$ write sys$output "will result in linker warning messages about mismatched
$ write sys$output "psect attributes."
$!
$ C_DEFS :="""VMS"""
$! C_DEFS :="""VMS""","""const="""
$ C_INCLUDES :=/include=([],[.config],[-.include],[-.include.aout])
$ C_FLAGS := /debug 'c_includes'
$!
$!
$ if "''p1'" .eqs. "LINK" then goto Link
$!
$!  This helps gcc 1.nn find the aout/* files.
$!
$ aout_dev = f$parse(flnm,,,"DEVICE")
$ tmp = aout_dev - ":"
$if f$trnlnm(tmp).nes."" then aout_dev = f$trnlnm(tmp)
$ aout_dir = aout_dev+f$parse(flnm,,,"DIRECTORY")' -
	- "GAS]" + "INCLUDE.AOUT.]" - "]["
$assign 'aout_dir' aout/tran=conc
$ opcode_dir = aout_dev+f$parse(flnm,,,"DIRECTORY")' -
	- "GAS]" + "INCLUDE.OPCODE.]" - "]["
$assign 'opcode_dir' opcode/tran=conc
$!
EOF

cfiles="`echo $* | sed -e 's/\.o/.c/g' -e 's!../\([^ /]*\)/\([^ /]*\.c\)![-.\1]\2!g'`"

for cfile in $cfiles ; do
  echo "\$ gcc 'c_flags'/define=('C_DEFS') $cfile"
  case $cfile in
    "[-."*)  copyfiles="$copyfiles $cfile" ;;
  esac
done

for c in $copyfiles ; do
  base=`echo $c | sed -e 's/\[.*\]//' -e 's/\.c$//'`
  dir=`echo $c | sed 's/\].*$/]/'`
  echo "\$if f\$search(\"$base.obj\").eqs.\"\" then copy $dir$base.obj *.*"
done

cat << 'EOF'
$ link/nomap/exec=gcc-as version.opt/opt+sys$input:/opt
!
!	Linker options file for GNU assembler
!
EOF

for obj in $* ; do
  echo $obj,- | sed 's!.*/!!g'
done

cat << 'EOF'
gnu_cc:[000000]gcclib/lib,sys$share:vaxcrtl/lib
EOF
