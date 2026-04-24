//===- FunctionCallSummary.h - Summary for function calls ---------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//

#ifndef LLVM_CLANG_STATICANALYZER_COMPOSER_H
#define LLVM_CLANG_STATICANALYZER_COMPOSER_H

#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ASTFinder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/JsonSummaryManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/StringSplit.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/AST/ASTContext.h"
#include <cassert>
#include <vector>

namespace clang {
namespace ento {

typedef std::pair<llvm::APSInt,llvm::APSInt> rangePair;

class FD_Stream { // a tool used by Composer. It construct a fd_ostream.
public:
  FD_Stream(StringRef fileName) {
    std::error_code EC;
    pout = new llvm::raw_fd_ostream(fileName, EC);
    if (EC) {
      llvm::errs() << "warning: could not open file: " << EC.message() << '\n';
      exit(-1);
    }
  }
  ~FD_Stream() { delete pout; }
  llvm::raw_fd_ostream& get() { return *pout; }
private:
  llvm::raw_fd_ostream* pout;
};


class Composer {
  // 此处定义一个函数指针类型， 指向Composer类的成员函数
  typedef SVal (Composer::*ComposeFn)(StringRef) const;  

  ASTContext& Actx;
  SValBuilder& SVB;
  const CallEvent& CE;
  MemRegionManager& MemMgr;
  ProgramStateRef State;     // before call
  ProgramStateRef NowState;  // after some call processes

  const unsigned MaxCount; // used when compose SymbolConjured

  FD_Stream* pfdStream;
  llvm::raw_fd_ostream& out;

  static constexpr unsigned MaxItemNum = 100;  // 一个中括号中最多包含多少项

  const LocationContext* Lctx;
  const VarDecl* CallerReturnVar;

  ComposeFn dispatchSVal(StringRef name) const;
  ComposeFn dispatchSubRegion(StringRef name) const;
  ComposeFn dispatchSymbol(StringRef name) const;

  #define SVAL_FN(ClassName) \
    SVal compose##ClassName(StringRef name) const;
  
  SVAL_FN(MemRegionVal)
  SVAL_FN(UnknownVal)
  SVAL_FN(UndefinedVal)
  SVAL_FN(ConcreteIntLoc)
  SVAL_FN(ConcreteIntNonLoc)
  SVAL_FN(SymbolVal)
  SVAL_FN(LocAsInteger)
  SVAL_FN(LazyCompoundVal)

  #define MEMREGION_FN(ClassName) \
    SVal compose##ClassName(StringRef name) const;

  MEMREGION_FN(SymbolicRegion)
  MEMREGION_FN(ElementRegion)
  MEMREGION_FN(FieldRegion)
  MEMREGION_FN(VarRegion)
  MEMREGION_FN(StringRegion)
  MEMREGION_FN(FunctionCodeRegion)

  #define SYMBOL_FN(ClassName) \
    SVal compose##ClassName(StringRef name) const;

  SYMBOL_FN(SymbolRegionValue)
  SYMBOL_FN(BinarySymExpr)
  SYMBOL_FN(SymbolConjured)

  // help function for composeBinarySymbolVal
  SVal composeOneSide(StringRef name) const; 
  BinaryOperator::Opcode composeOpcode(StringRef name) const;

  // help function for composeFieldRegion
  const FieldDecl* findFieldDecl(StringRef struct_name,
                                 StringRef field_name) const;
  
  // 某些API如getArgSVal会在无能为力时返回UnknownVal，此时应该替换为SummaryFailedVal
  SVal IdenticalButNotUnknown(SVal S) const;

  bool isMallocReturnVal(SVal S) const;

  // commonType: (base|struct name) ('*')*
  // struct T**
  QualType makeCommonType(StringRef name) const;
  QualType makeArrayType(StringRef name) const;
  QualType makeBaseType(StringRef name) const;
  QualType makeStructType(StringRef name, bool isProbing) const;
  QualType makeFuncPtrType(StringRef name) const;
  bool isFuncPtrType(StringRef name) const;
  bool isArrayType(StringRef name) const;
  bool isCommonType(StringRef name) const;
  StringRef removeCVfromStr(StringRef name) const;
public:
  Composer(ASTContext& _Actx, SValBuilder& _SVB,
           MemRegionManager& _memMgr, const CallEvent& _callEvent,
           const ProgramStateRef& _state, unsigned _maxCount,
           StringRef logFileName, const LocationContext* _lctx, const VarDecl* _callerReturnVar) 
           : Actx(_Actx), SVB(_SVB), CE(_callEvent),
              MemMgr(_memMgr), State(_state), MaxCount(_maxCount),
              pfdStream(new FD_Stream(logFileName)), out(pfdStream->get()),
              Lctx(_lctx), CallerReturnVar(_callerReturnVar) {
  }

  Composer(const Composer&) = default;
  ~Composer() { delete pfdStream; }

  QualType makeType(StringRef name) const;

  SVal composeSVal(StringRef name, bool inner=false) const;
  SVal composeSubRegion(StringRef name, bool inner=false) const;
  SVal composeSymbol(StringRef name, bool inner=false) const;

  SVal composeConcreteInt(StringRef name, bool isNonLoc=true) const;
  void composeRange(StringRef name, std::vector<rangePair> &ranges) const;
  NonLoc composeLocAsInteger(Loc loc, unsigned bits) const;

  const MemSpaceRegion* composeMemSpace(StringRef name) const;

  // composeMemSpace和composeSubRegion的结合；
  // 返回SVal而不是MemRegion。原因是对于VarRegion，反序列化后会返回实参SVal
  // 并且失败后会返回SummaryFailed
  SVal composeMemRegion(StringRef name) const; 

  bool ostreamHasError();
  void setNowState(const ProgramStateRef& nowState) { NowState = nowState; }
};
} // end of ento namespace
} // end of clang namespace

#endif // LLVM_CLANG_STATICANALYZER_COMPOSER_H
