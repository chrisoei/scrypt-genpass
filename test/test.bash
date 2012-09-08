#!/bin/bash

PROG=./scrypt-genpass
RESULTS=test/test_results.log

$PROG -t > $RESULTS 2>&1
$PROG -h >> $RESULTS 2>&1
$PROG -p b a >> $RESULTS 2>&1
$PROG -k test/keyfile1.dat -p abc ghi >> $RESULTS 2>&1
$PROG -l 2 -p a a >> $RESULTS 2>&1
$PROG -l 65 -p a a >> $RESULTS 2>&1
$PROG -l 64 -p a a >> $RESULTS 2>&1
$PROG -l 4 -p "Speak, friend, and enter." "The Doors of Durin" >> $RESULTS 2>&1

diff $RESULTS test/test_results.reference
