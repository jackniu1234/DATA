# 不使用虚拟机

## Ghidra环境部署
1. 下载Ghidra 11.3 版本 source code，基于以下链接安装开发环境
https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_11.3_build/DevGuide.md
2. 对Ghidra source code Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc做一行修改： 
> const char *firstmem[] = { "base", "protorecovery", "protorecovery_b", "fixateproto", "deadcode", "analysis", "subvar", "" };
3. 如果在GUI中运行脚本(Window->Script Manager) ，需要将当前目录添加到Ghidra的脚本path中。

## 约定
1. 每个测试用例对应一个工作目录，工作目录命名可参考源码，工作目录中会生成调试文件，与输入文件（如all_icalls.json），结果文件
2. 在运行脚本之前，应该保证项目内的文件已被Ghidra内置分析
3. 每个脚本都包含硬编码的path，需要提前修改
4. headless命令在本实验中用于测试用例的批处理，使用方式为headless <项目路径> <项目> -noanalysis -scriptPath <脚本目录> -preScript <脚本>
5. SPEC2k6不支持重新编译，因为里面有一些修复反编译结果的逻辑，使用了文件名与地址的硬编码

## 运行SPEC2k6间接调用实验
1. 下载数据集(spec-gcc/bin)，构造工作目录与Ghidra项目，注意gt.json位于工作目录
2. 对于每一个程序，执行find_icalls.py脚本，生成all_icalls.json
3. 运行/home/jackniu/ghidra-master/build/dist/ghidra_11.3_DEV/support/analyzeHeadless /home/jackniu/project second -noanalysis -scriptPath "/home/jackniu/scripts/code/" -postScript "TestUnification.java"
4. 查看总结果文件与每个测试用例的结果文件 

## 运行EmTaint间接调用实验
1. 下载数据集(emtaints/firmware-binaries)，构造工作目录与Ghidra项目
2. 对于每一个程序，执行find_icalls.py脚本，生成all_icalls.json
3. 运行headless TestEmTaintUnification.java
4. 查看总结果文件与每个测试用例的结果文件 

## 运行跳表恢复实验
1. 下载数据集(spec-gcc/bin)，构造工作目录与Ghidra项目，注意工作目录中包含xxx_gt.csv
2. 修改TestSJA.java指定测试的优化等级
3. 运行headless TestSJA.java
4. 将每个程序的结果文件组织为一个目录，拷贝到到SJA的虚拟机（https://zenodo.org/records/12670597  )，魔改其测试文件（参考sja/run.sh与sja/eval.cpp），导出分析结果

## 运行PTA test cases

1. 下载数据集(cases/arm-O0/bin)，构造工作目录
2. 运行/home/jackniu/ghidra-master/build/dist/ghidra_11.3_DEV/support/analyzeHeadless /home/jackniu/project <项目名> -import <程序所在目录>以创建Ghidra project，触发Ghidra自动分析并保存
3. 修改TestPTA.java指定测试对象，arm-O0 or x64-O0
4. 运行headless "TestPTA.java"
5. 进入运行结果目录，执行csvdiff result.csv tasks.csv，查看运行结果是否符合预期的tasks.csv

# 使用虚拟机
密码zwt666

## 运行SPEC2k6间接调用实验
1. headless /home/jackniu/project spec-gcc -noanalysis -scriptPath "/home/jackniu/scripts/code/" -preScript "TestUnification.java"
2. 在~/scripts/spec-gcc中查看result.csv

## 运行EmTaint间接调用实验
1. headless /home/jackniu/project emtaint -noanalysis -scriptPath "/home/jackniu/scripts/code/" -preScript "TestEmtaintUnification.java"
2. 在~/scripts/emtaints中查看result.csv

## 运行跳表恢复实验

1. headless /home/jackniu/project third -scriptPath "/home/jackniu/scripts/code/" -noanalysis -postScript "TestPTA.java"
2. 将每个程序的结果文件组织为一个目录，拷贝到到SJA的虚拟机（https://zenodo.org/records/12670597  )，魔改其测试文件（参考sja/run.sh与sja/eval.cpp），导出分析结果
