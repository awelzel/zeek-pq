# @TEST-EXEC: zeek -NN Zeek::PQ |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
