#!/bin/bash

set -e
set -u

cat log_gcov | awk -f convert_gcov.awk -v RS='\r\n'
for i in `find . -name '*.xxd'`;do
	cat "$i" | xxd -r -p > "${i/\.xxd/}"
	rm "$i"
done

[[ -e "gcov_out" ]] && rm -rf gcov_out
mkdir gcov_out

for i in `find . -name '*.gcda'`;do
	${TOOLCHAIN_PREFIX}gcov -a "$i"
done

gcovr --html --html-details -o gcov_out/idx.html -r . -g
rm *.gcov
