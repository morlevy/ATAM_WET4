#!/bin/bash

mkdir -p results

status=$?

src_file_arr=("test0_sanity.c" "test1_mult.c" "test2_recursion.c" "test3_no_symbol.c" "test4_return_value.c" "test5_not_global.c" "test6_internal_call.c" "test7_mutual_recursion.c" "test8_call_by_pointer.c" "test9_while_foo.c" "test10_cmdline_args.c")
target_func=("foo" "foo" "rec_foo" "DNE" "foo" "noneOfYourBusiness" "foo" "mut_rec_foo" "foo" "foo" "foo")

echo "Static tests:"
for i in ${!src_file_arr[@]}; do
  gcc -no-pie -std=c99 -w -o out ./test_src_files/${src_file_arr[$i]} ./test_src_files/library.c -Wl,-zlazy
  ./prf ${target_func[$i]} out 12345 12345 12345 12345 > ./results/res_static_$i
  if diff -q ./results/res_static_$i ./expected/exp_static_$i > /dev/null;
  then 
    echo "Test $i passed" 
  else 
    echo "Test $i failed" 
  fi
done

gcc -fPIC -shared -std=c99 -w -o libtest_atam_hw3.so ./test_src_files/library.c
sudo mv libtest_atam_hw3.so /usr/lib/ > /dev/null

echo "--------------------------------------"

echo "Dynamic tests:"
for i in ${!src_file_arr[@]}; do
  gcc -no-pie -std=c99 -w -o out ./test_src_files/${src_file_arr[$i]} /usr/lib/libtest_atam_hw3.so -Wl,-zlazy
  ./prf ${target_func[$i]} out "DYNAMIC" "DYNAMIC" "DYNAMIC" "DYNAMIC" > ./results/res_dynamic_$i
  if diff -q ./results/res_dynamic_$i ./expected/exp_dynamic_$i > /dev/null;
  then 
    echo "Test $i passed" 
  else 
    echo "Test $i failed" 
  fi
done

rm out
