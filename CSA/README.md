# llvm-15.04

## build project

```bash
mkdir build && cd build
cmake -S ../llvm -B . -DLLVM_ENABLE_PROJECTS="clang" -DCMAKE_BUILD_TYPE=Debug
cmake --build . -j32
```

## register checker

1. 在```llvm-project/clang/lib/StaticAnalyzer/Checkers/```该目录下添加自己的checker.cpp(写checker可以参照文件夹内的checker)
2. 在checker的代码中使用checkerManager进行注册。
    ```cpp
        void ento::registerSummaryDumper(CheckerManager &mgr) {
            mgr.registerChecker<SummaryDumper>();
        }

        bool ento::shouldRegisterSummaryDumper(const CheckerManager &mgr) {
            return true;
        }
    ```
3. 其次```llvm-project/clang/include/clang/StaticAnalyzer/Checkers/Checkers.td```修改该文件的内容，将要注册的checker添加进去。
4. 最终，修改```llvm-project/clang/lib/StaticAnalyzer/Checkers/CMakeLists.txt```中的内容，将要注册的chekcer源文件添加进去。

完成这四步，就可以成功注册一个checker,当然，需要重新编译整个项目。

## defined checkers

1. alpha.core.DumpSummary