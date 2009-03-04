#!/bin/sh

t1=`mktemp`
t2=`mktemp`

ls *.c | tr [A-Z] [a-z] | sort > $t1
cat $t1 | sort -u > $t2
for f in `diff $t1 $t2 | grep "< " | awk -F"< " '{print $2}'`; do
	n=`echo $f | sed -e 's/t_/t_2/g'`;
	"Renaming $f --> $n.";
	p4 integrate $f $n;
	p4 delete $f;
done;

rm -f $t1 $t2


