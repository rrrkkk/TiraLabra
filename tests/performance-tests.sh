#!/bin/sh

# rypto performance tests

echo "rypto performance tests running"

rypto="../build/exe/rypto/passing/rypto"
sizes="10000000 20000000 30000000 40000000"

for i in $sizes; do
    echo " creating $i:"
    dd if=/dev/zero of=in.$i bs=$i count=1
done

for i in $sizes; do
    plain="in.$i"
    out="cipher.$i"
    echo " reference encrypt $i:"
    time -p openssl enc -e -nosalt -aes-128-ecb -K `cat key` -in $plain -out $out
    echo
done

for i in $sizes; do
    cipher="cipher.$i"
    out="out.$i"
    echo " reference decrypt $i:"
    time -p openssl enc -d -nosalt -aes-128-ecb -K `cat key` -in $cipher -out $out
    echo
done

for i in $sizes; do
    plain="in.$i"
    out="cipher.$i"
    echo " rypto encrypt $i:"
    time -p $rypto e `cat key` $plain $out
    echo
done

for i in $sizes; do
    cipher="cipher.$i"
    out="out.$i"
    echo " rypto decrypt $i:"
    time -p $rypto d `cat key` $cipher $out
    echo
done

# clean tmp files
rm -f in.* out.* cipher.*

echo "performance tests done"

