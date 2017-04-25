#!/bin/sh

# rypto integration tests

echo "rypto integration tests running"

rypto="../build/exe/rypto/passing/rypto"
failed=0
succesful=0

for i in 1 10 16 1506; do
    plain="plain.$i"
    out="rypto.$i"
    ref="openssl.$i"
    echo " encrypt $plain:"
    $rypto e `cat key` $plain $out
    cmp $ref $out
    if [ $? = 0 ]; then
	succesful=`expr $succesful + 1`
	echo "  success"
    else
	failed=`expr $failed + 1`
	echo "  fail"
    fi
    cipher="openssl.$i"
    out="rypto.$i"
    ref="plain.$i"
    echo " decrypt $cipher:"
    $rypto d `cat key` $cipher $out
    cmp $ref $out
    if [ $? = 0 ]; then
	succesful=`expr $succesful + 1`
	echo "  success"
    else
	failed=`expr $failed + 1`
	echo "  fail"
    fi
done

# clean tmp files
rm -f rypto.1*

echo "integration tests done: succesful $succesful, failed $failed"

