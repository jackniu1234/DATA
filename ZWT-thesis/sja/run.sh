#!/bin/bash

# +------------+---------------------------------------------+
# |  sja_mode  |            description                      |
# +------------+---------------------------------------------+
# |     1      |  sja's domain + bidirectional constraints   |
# |     2      |  sja's domain + unidirectional constraints  |
# |     3      |  vsa's domain + bidirectional constraints   |
# |     4      |  vsa's domain + unidirectional constraints  |
# +------------+---------------------------------------------+
#
# Table 1, Fig.8, Fig.9: Use sja_mode = 1
# Table 2: Compare sja_mode = 4 vs sja_mode = 2
# Table 3: Compare sja_mode = 2 vs sja_mode = 1
# NOTE: 3rd column in Table 2 is "Our domain D, *Unidirectional* constraints" (typo in pdf)

sja_mode=$1

if [[ $sja_mode -eq 1 ]]; then
   cp ~/artifact/sja/SBA/config_bicstr.h ~/artifact/sja/SBA/config.h
   cp ~/artifact/sja/SBA/domain_sja.cpp ~/artifact/sja/SBA/domain.cpp
elif [[ $sja_mode -eq 2 ]]; then
   cp ~/artifact/sja/SBA/config_unicstr.h ~/artifact/sja/SBA/config.h
   cp ~/artifact/sja/SBA/domain_sja.cpp ~/artifact/sja/SBA/domain.cpp
elif [[ $sja_mode -eq 3 ]]; then
   cp ~/artifact/sja/SBA/config_bicstr.h ~/artifact/sja/SBA/config.h
   cp ~/artifact/sja/SBA/domain_vsa.cpp ~/artifact/sja/SBA/domain.cpp
elif [[ $sja_mode -eq 4 ]]; then
   cp ~/artifact/sja/SBA/config_unicstr.h ~/artifact/sja/SBA/config.h
   cp ~/artifact/sja/SBA/domain_vsa.cpp ~/artifact/sja/SBA/domain.cpp
fi

# create working directory
dir=/tmp/sja
rm -rf $dir/*
mkdir -p $dir/0

# build sja
# cd ~/artifact/sja/lift; make clean; make all
# cd ~/artifact/sja/SBA; make clean; make all

# build evaluation program
g++ -g -std=c++2a ~/artifact/sja/eval.cpp -o $dir/eval

# generate list of target binaries in ~/dataset
# echo /home/sja/dataset/gcc_Of/du/  > $dir/dlist
find ~/dataset/gcc_O0 -executable -type f | grep "ori$" | rev | cut -d '/' -f2- | rev > $dir/dlist
# find ~/dataset -executable -type f | grep "ori$" | rev | cut -d '/' -f2- | rev > $dir/dlist

# convert hex to dec
hex2dec() {
   {
      echo 'ibase=16';
      sed -e 'y/xabcdef/XABCDEF/' -e 's/^0X//';
   } | bc
}

while read -r dpath <&3
do

   name=$(basename "$dpath")
   echo $name

   # # modify from here
   # # 只处理指定前缀的 case
   # case "$name" in
   #    ld.gold)
   #       ;;              # 匹配到：什么都不做，继续往下跑
   #    *)
   #       continue        # 其他全部跳过
   #       ;;
   # esac
   # echo $name
   # # modify end here

   # clean up working directory, strip binaries
   rm -rf $dir/0/*
   cp $dpath/ori $dir/0/ori
   strip -s $dir/0/ori -o $dir/0/obj  # raw 'ori', stripped 'obj'


   # dump binary, gt, sba.icf;
   # modify from here
   # tar -C $dir/0 -xf $dpath/log_gt.tar.xz
   # objdump --prefix-addresses -d $dir/0/ori | grep '^0' > $dir/0/obj.s # used by eval.cpp
   # $dir/eval $dir/0 dec 0.9 1.1
   # mv $dir/0/gt_standard.csv $dir/${name}_gt.csv
   # /usr/bin/time -v -o $dir/0/runtime.sba ~/artifact/sja/SBA/test_jtable 0 >/dev/null 2>&1
   # sort -u $dir/0/sba.jtable -o $dir/0/sba.jtable                      # remove duplicate
   # mv $dir/0/obj $dir/${name}_obj
   # mv $dir/0/sba.icf $dir/${name}_sba.icf
   # mv $dir/0/sba.jtable $dir/${name}_sba.jtable
   # continue
   # modify end here


   # groundtruth and competitors
   tar -C $dir/0 -xf $dpath/log_gt.tar.xz
   # tar -C $dir/0 -xf $dpath/log_angr.tar.xz
   tar -C $dir/0 -xf $dpath/log_dyninst.tar.xz
   tar -C $dir/0 -xf $dpath/log_ghidra.tar.xz
   # tar -C $dir/0 -xf $dpath/log_ddisasm.tar.xz
   cp $dpath/runtime* $dir/0

   # sja
   #
   # +--------------------------+-------------------------------------------+
   # |           output         |                description                |
   # +--------------------------+-------------------------------------------+
   # |  /tmp/sja/0/runtime.sba  |  runtime performance                      |
   # |  /tmp/sja/0/sba.icf      |  {jump address, {target1, target2, ...}}  |
   # |  /tmp/sja/0/sba.jtable   |  {jtable base, {target1, target2, ...}}   |
   # +--------------------------+-------------------------------------------+
   #
   # 1. args '0' means run inside /tmp/sja/0
   #    ::note:: sja can run in parallel, but requires more RAM than current machine
   #
   # 2. sja always analyzes /tmp/sja/0/obj (stripped)
   #    ::verify:: main() in ~/artifact/sja/SBA/main/test_jtable.cpp
   #
   /usr/bin/time -v -o $dir/0/runtime.sba ~/artifact/sja/SBA/test_jtable 0 >/dev/null 2>&1

   # evaluation
   #
   # 1. args
   #    '$dir/0': evaluate /tmp/sja/0
   #    'dec'   : display results in decimal
   #    '0.5'   : set lower threshold to 50% (Fig.9)
   #    '2.0'   : set higher threshold to 200% (Fig.9)
   #
   # 2. result: /tmp/sja/0/eval.<tool>
   # +--------------------------+-----------------------------------------------+
   # |           tags           |                description                    |
   # +--------------------------+-----------------------------------------------+
   # |  jtentry_gt              |  #jtable_entry in groundtruth                 |
   # |  jtentry_correct_<tool>  |  #jtable_entry correctly found by <tool>      |
   # |  jtentry_over_<tool>     |  #jtable_entry overestimated by <tool> (FPs)  |
   # |  jtentry_under_<tool>    |  #jtable_entry missed by <tool> (FNs)         |
   # +--------------------------+-----------------------------------------------+
   # *** eval.<tool> includes other details, e.g., which jump tables are missed by <tool>
   # *** uncomment the last command (read -p ...) to see detailed results at /tmp/sja/0
   #
   objdump --prefix-addresses -d $dir/0/ori | grep '^0' > $dir/0/obj.s # used by eval.cpp
   sort -u $dir/0/sba.jtable -o $dir/0/sba.jtable                      # remove duplicate
   awk '{
      for(i=1;i<=NF;i++) {
         printf "%x ", $i
      }
      printf "\n"
   }' $dir/0/sba.icf | tee $dir/0/sba.icf 1>/dev/null

   # modify from here
   if [ ! -f "/home/sja/artifact/jump-O0-result/${name}_result.txt" ]; then
      echo "$name" >> $dir/miss.txt
   fi
   $dir/eval $dir/0 dec 0.5 2.0 "/home/sja/artifact/jump-O0-result/${name}_result.txt"
   # $dir/eval $dir/0 dec 0.9 1.1 "/home/sja/artifact/jump-O0-result/${name}_result.txt"
   # modify end

   # collect results
   #
   # +--------------------+-----------------------+
   # |       file         |       results         |
   # +--------------------+-----------------------+
   # |  /tmp/sja/bounds   |  jump table entries   |
   # |  /tmp/sja/bases    |  jump table bases     |
   # +--------------------+-----------------------+
   #
   echo $dpath >> $dir/bounds

   grep "jtentry_gt:" $dir/0/eval.sba >> $dir/bounds
   grep "jtentry_correct_" $dir/0/eval.* | cut -d':' -f2- >> $dir/bounds
   grep "jtentry_over_" $dir/0/eval.* | cut -d':' -f2- >> $dir/bounds
   grep "jtentry_under_" $dir/0/eval.* | cut -d':' -f2- >> $dir/bounds
   nm -S $dir/0/ori | grep '^0' | grep -E ' T | t ' | sed 's/^0*//' | awk '{print $2}' | hex2dec | sort -rn | head -n 1 | awk '{print "#max_func_size:",$1}' >> $dir/bounds
   echo $dpath >> $dir/bases
   grep "jtbase_gt" $dir/0/eval.sba >> $dir/bases
   grep "jtbase_correct_" $dir/0/eval.* | cut -d':' -f2- >> $dir/bases
   # read -p "Press enter to continue"
done 3<$dir/dlist