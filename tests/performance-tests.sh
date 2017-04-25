#!/bin/sh

# rypto performance tests

echo "rypto performance tests running"

rypto="../build/exe/rypto/passing/rypto"

for i in 100000 1000000 10000000; do
    echo " creating $i:"
    dd if=/dev/zero of=in.$i bs=$i count=1
done

for i in 100000 1000000 10000000; do
    plain="in.$i"
    out="cipher.$i"
    echo " encrypt $i:"
    time $rypto e `cat key` $plain $out
    echo
    echo
done

for i in 100000 1000000 10000000; do
    cipher="cipher.$i"
    out="out.$i"
    echo " decrypt $i:"
    time $rypto d `cat key` $cipher $out
    echo
    echo
done

# clean tmp files
rm -f in.100000* out.100000* cipher.100000*

echo "performance tests done"

