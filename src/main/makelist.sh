#! /bin/sh
#
# makelist.sh	Output static module array.
#

mods=`echo $* | sed -e 's/\.[coa]//g' -e 's/\.so//g'`

for i in $mods
do
	echo "extern module_t $i;"
done
echo
echo "static_modules_t static_modules[] = {"
for i in $mods
do
	echo "  {  \"$i.c\", &$i  },"
done
echo "  {  NULL, NULL  }"
echo "};"

