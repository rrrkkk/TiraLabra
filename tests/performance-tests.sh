#!/bin/sh

# rypto performance tests

echo "rypto performance tests running"

rypto="../build/exe/rypto/passing/rypto"
sizes="10000000 20000000 30000000"

for i in $sizes; do
    echo " creating $i:"
    dd if=/dev/zero of=in.$i bs=$i count=1
done

for i in $sizes; do
    plain="in.$i"
    out="cipher.$i"
    echo " encrypt $i:"
    time -p $rypto e `cat key` $plain $out
    echo
    echo
done

for i in $sizes; do
    cipher="cipher.$i"
    out="out.$i"
    echo " decrypt $i:"
    time -p $rypto d `cat key` $cipher $out
    echo
    echo
done

# clean tmp files
rm -f in.* out.* cipher.*

echo "performance tests done"

