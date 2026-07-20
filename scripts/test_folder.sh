#!/bin/sh

password=secret123
base=tmp/folder_test

rm -fr $base
mkdir -p $base/src/subdir/deep

# Source tree:
#   src/file1.txt
#   src/file2.bin
#   src/empty.txt        (empty — must be skipped)
#   src/subdir/nested.txt
#   src/subdir/deep/deep.dat

dd if=/dev/urandom of=$base/src/file1.txt bs=1024 count=1 2>/dev/null
dd if=/dev/urandom of=$base/src/file2.bin bs=1024 count=10 2>/dev/null
touch $base/src/empty.txt
dd if=/dev/urandom of=$base/src/subdir/nested.txt bs=512 count=1 2>/dev/null
dd if=/dev/urandom of=$base/src/subdir/deep/deep.dat bs=256 count=1 2>/dev/null

sha1_file1=$(shasum $base/src/file1.txt | cut -d' ' -f1)
sha1_file2=$(shasum $base/src/file2.bin | cut -d' ' -f1)
sha1_nested=$(shasum $base/src/subdir/nested.txt | cut -d' ' -f1)
sha1_deep=$(shasum $base/src/subdir/deep/deep.dat | cut -d' ' -f1)

# -----------------------------------------------------------------------
echo "=== Test: Encrypt with -o (output folder created automatically) ==="
./vsencrypt -e -i $base/src -o $base/enc -p $password
if [ $? -ne 0 ]; then echo "FAIL: encrypt with -o returned error"; exit 1; fi

[ -f $base/enc/file1.txt.vse ]              || { echo "FAIL: enc/file1.txt.vse not created"; exit 1; }
[ -f $base/enc/file2.bin.vse ]              || { echo "FAIL: enc/file2.bin.vse not created"; exit 1; }
[ -f $base/enc/subdir/nested.txt.vse ]      || { echo "FAIL: enc/subdir/nested.txt.vse not created"; exit 1; }
[ -f $base/enc/subdir/deep/deep.dat.vse ]   || { echo "FAIL: enc/subdir/deep/deep.dat.vse not created"; exit 1; }
[ ! -f $base/enc/empty.txt.vse ]            || { echo "FAIL: enc/empty.txt.vse should not exist (empty file skipped)"; exit 1; }

# -----------------------------------------------------------------------
echo "=== Test: Decrypt with -o (mirror tree) ==="
./vsencrypt -d -i $base/enc -o $base/dec -p $password
if [ $? -ne 0 ]; then echo "FAIL: decrypt with -o returned error"; exit 1; fi

[ -f $base/dec/file1.txt ]              || { echo "FAIL: dec/file1.txt not created"; exit 1; }
[ -f $base/dec/file2.bin ]              || { echo "FAIL: dec/file2.bin not created"; exit 1; }
[ -f $base/dec/subdir/nested.txt ]      || { echo "FAIL: dec/subdir/nested.txt not created"; exit 1; }
[ -f $base/dec/subdir/deep/deep.dat ]   || { echo "FAIL: dec/subdir/deep/deep.dat not created"; exit 1; }

[ "$(shasum $base/dec/file1.txt | cut -d' ' -f1)" = "$sha1_file1" ]       || { echo "FAIL: file1.txt SHA1 mismatch"; exit 1; }
[ "$(shasum $base/dec/file2.bin | cut -d' ' -f1)" = "$sha1_file2" ]       || { echo "FAIL: file2.bin SHA1 mismatch"; exit 1; }
[ "$(shasum $base/dec/subdir/nested.txt | cut -d' ' -f1)" = "$sha1_nested" ] || { echo "FAIL: nested.txt SHA1 mismatch"; exit 1; }
[ "$(shasum $base/dec/subdir/deep/deep.dat | cut -d' ' -f1)" = "$sha1_deep" ] || { echo "FAIL: deep.dat SHA1 mismatch"; exit 1; }

# -----------------------------------------------------------------------
echo "=== Test: -o pointing to an existing file should fail ==="
touch $base/notadir
./vsencrypt -e -i $base/src -o $base/notadir -p $password 2>/dev/null
if [ $? -eq 0 ]; then echo "FAIL: should have rejected -o that is an existing file"; exit 1; fi

# -----------------------------------------------------------------------
echo "=== Test: In-place recursive (no -o) ==="
mkdir -p $base/inplace/subdir/deep
cp $base/src/file1.txt        $base/inplace/file1.txt
cp $base/src/file2.bin        $base/inplace/file2.bin
cp $base/src/subdir/nested.txt     $base/inplace/subdir/nested.txt
cp $base/src/subdir/deep/deep.dat  $base/inplace/subdir/deep/deep.dat

./vsencrypt -e -i $base/inplace -p $password
if [ $? -ne 0 ]; then echo "FAIL: in-place encrypt returned error"; exit 1; fi

[ -f $base/inplace/file1.txt.vse ]             || { echo "FAIL: inplace/file1.txt.vse not created"; exit 1; }
[ -f $base/inplace/subdir/nested.txt.vse ]     || { echo "FAIL: inplace/subdir/nested.txt.vse not created"; exit 1; }
[ -f $base/inplace/subdir/deep/deep.dat.vse ]  || { echo "FAIL: inplace/subdir/deep/deep.dat.vse not created"; exit 1; }

# Remove originals so decrypt can write them back
rm $base/inplace/file1.txt $base/inplace/file2.bin \
   $base/inplace/subdir/nested.txt $base/inplace/subdir/deep/deep.dat

./vsencrypt -d -i $base/inplace -p $password
if [ $? -ne 0 ]; then echo "FAIL: in-place decrypt returned error"; exit 1; fi

[ "$(shasum $base/inplace/file1.txt | cut -d' ' -f1)" = "$sha1_file1" ]            || { echo "FAIL: inplace file1.txt SHA1 mismatch"; exit 1; }
[ "$(shasum $base/inplace/file2.bin | cut -d' ' -f1)" = "$sha1_file2" ]            || { echo "FAIL: inplace file2.bin SHA1 mismatch"; exit 1; }
[ "$(shasum $base/inplace/subdir/nested.txt | cut -d' ' -f1)" = "$sha1_nested" ]   || { echo "FAIL: inplace nested.txt SHA1 mismatch"; exit 1; }
[ "$(shasum $base/inplace/subdir/deep/deep.dat | cut -d' ' -f1)" = "$sha1_deep" ]  || { echo "FAIL: inplace deep.dat SHA1 mismatch"; exit 1; }

echo "=== All folder tests passed ==="
