//===- FunctionCallSummary.h - Summary for function calls ---------*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//

#ifndef LLVM_CLANG_STATICANALYZER_SUMMARYRELATED_H
#define LLVM_CLANG_STATICANALYZER_SUMMARYRELATED_H

#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Composer.h"
#include "llvm/ADT/PointerIntPair.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/StringRef.h"
#include "clang/AST/ASTContext.h"
#include <cassert>
#include <vector>
#include <memory>

namespace clang {
namespace ento {

using std::shared_ptr;
using std::make_shared;

class Reader {
  std::string filename;
public:
  Reader(std::string F) : filename(F) {}
  std::string getFilename() const { return filename; }
  std::vector<std::string> getStrings() const;
};

// 存放一条路径下得到的仅未处理GDM时的State，与CheckerDatas的bind
typedef std::pair<ProgramStateRef, std::map<std::string, void*>> StateAndCKSummaryPair; 

typedef void* (*CheckerDataComposeFn)(const std::vector<std::string>&, const Composer&);  

void doComposeSVal(const Reader& reader, const Composer& composer);
void* doComposeMallocCheckerData(const Reader& reader, const Composer& composer);
void* doComposeMallocCheckerData(const std::vector<std::string>& serializeStrings, const Composer& composer);
CheckerDataComposeFn dispatchCheckerComposer(const std::string& name);

std::vector<StateAndCKSummaryPair> doComposePaths (const CallEvent& CE, const JsonSummary& summary, Composer& composer);
int64_t ElementOffsetToInt(uint64_t offset, uint64_t typeSize);

bool callEventMatchSummary(const CallEvent&, StringRef opts, 
                           std::string& path);   // path为出参
bool callEventMatchSummary(const CallEvent& CE, JsonSummaryManager& JSM, JsonSummaryKey& JSK);

// 获得return value对应的左值的varDecl
const VarDecl* getReturnVarDecl(ExprEngine& Eng, const CallEvent& Call); 
shared_ptr<Composer> makeOneComposer(ExprEngine& Eng, const CallEvent& Call, const ExplodedNode* Pred);

} // end of ento namespace
} // end of clang namespace


#endif // LLVM_CLANG_STATICANALYZER_SUMMARYRELATED_H
