//===- FunctionCallSummary.h - Summary for function calls ---------*- C++ -*--//
//
//           The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//

#ifndef LLVM_CLANG_STATICANALYZER_MALLOCCHECKERDATA_H
#define LLVM_CLANG_STATICANALYZER_MALLOCCHECKERDATA_H

#include "clang/StaticAnalyzer/Core/PathSensitive/Composer.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Optional.h"
#include <vector>

namespace clang {
namespace ento {
class MallocCheckerData {
  enum Kind{Malloc, Free};

  Kind K;
  unsigned Family_idx;  // index of MallocChecker.cpp::AllocationFamily

  // used when K == Malloc
  SVal HeapConjVal;     // 一个SymbolicRegionVal，其MemRegion是一个ConjuredSymbol，位于Heap空间
  SVal SizeVal;

  // used when K == Free
  SVal FreeVal;       

  MallocCheckerData(SVal HV, SVal SV, unsigned Fidx)
    : K(Malloc), Family_idx(Fidx), HeapConjVal(HV), SizeVal(SV) {
  }
  MallocCheckerData(SVal S, unsigned Fidx)
    : K(Free), Family_idx(Fidx), FreeVal(S) {
  }

public:
  bool isMallocData() const {return K == Malloc;}
  bool isFreeData() const {return K == Free;}

  unsigned getFamilyIdx() const { return Family_idx; }
  SVal getHeapConjVal() const { return HeapConjVal; }
  SVal getSizeVal() const { return SizeVal; }
  SVal getFreeVal() const { return FreeVal; }

  static MallocCheckerData CreateMallocData(SVal HV, SVal SV, unsigned Fidx) {
    return MallocCheckerData(HV, SV, Fidx);
  }
  static MallocCheckerData CreateFreeData(SVal S, unsigned Fidx) {
    return MallocCheckerData(S, Fidx);
  }
  
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
    ID.AddInteger(Family_idx);
    if (isFreeData()) {
      FreeVal.Profile(ID);
    }
    else {
      HeapConjVal.Profile(ID);
      SizeVal.Profile(ID);
    }
  }

  bool operator==(const MallocCheckerData& Rhs) const {
    if (Rhs.K != K || Rhs.Family_idx != Family_idx)
      return false;
    
    if (isFreeData()) {
      return Rhs.FreeVal == FreeVal;
    }
    else {
      return Rhs.HeapConjVal == HeapConjVal && Rhs.SizeVal == SizeVal;
    }
  }

  static llvm::Optional<MallocCheckerData> Deserialize(
                              const Composer& C, StringRef name) {
    std::vector<StringRef> vec = commaSplit(name, 4);
    if (vec[0] == "malloc") {
      SVal heapConjVal = C.composeSVal(vec[1]);
      SVal sizeVal = C.composeSVal(vec[2]);
      unsigned family;
      bool has_error = vec[3].getAsInteger(10, family);

      if (heapConjVal.isSummaryFailed() || sizeVal.isSummaryFailed() || has_error)
        return llvm::None;
      
      return CreateMallocData(heapConjVal, sizeVal, family);;
    }
    else if (vec[0] == "free") {
      SVal freeVal = C.composeSVal(vec[1]);
      unsigned family;
      bool has_error = vec[2].getAsInteger(10, family);

      if (freeVal.isSummaryFailed() || has_error)
        return llvm::None;

      return CreateFreeData(freeVal, family);
    }
    else {
      llvm_unreachable("MallocCheckerData::Deserialize meets illegle datas");
    }
  }

  void dumpToStream(raw_ostream &os) const {
    if (isFreeData()) {
      os << "free,";
      FreeVal.customDumpToStream(os);
      os << "," << Family_idx;
    }
    else {
      os << "malloc,";
      HeapConjVal.customDumpToStream(os);
      os << ",";
      SizeVal.customDumpToStream(os);
      os << "," << Family_idx;
    }
  }
  void dump() const { dumpToStream(llvm::errs()); }
};
using MallocCheckerDatas = std::vector<MallocCheckerData>;

} // end of ento namespace
} // end of clang namespace

#endif // LLVM_CLANG_STATICANALYZER_MALLOCCHECKERDATA_H
