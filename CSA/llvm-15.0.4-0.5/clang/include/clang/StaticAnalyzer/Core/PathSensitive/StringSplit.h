#ifndef LLVM_CLANG_STATICANALYZER_STRINGSPLIT_H
#define LLVM_CLANG_STATICANALYZER_STRINGSPLIT_H

#include "llvm/ADT/StringRef.h"
#include <vector>

namespace clang {
namespace ento {

using namespace llvm;

// commaSplit与StringRef.split(',')的不同点在于前者的逗号是有层级的，
// 只利用位于第一层的逗号进行分割

// 分为num份, maxNum>num>1
std::vector<StringRef> commaSplit(StringRef ss, unsigned num, const unsigned MaxNum=100);
std::pair<StringRef, StringRef> commaSplit(StringRef ss); // 分为两份
StringRef trimOuterBracket(StringRef ss);
StringRef trimHeadAndTail(StringRef ss, StringRef head, StringRef tail);
StringRef removeFirstAndLastCh(StringRef ss);

} // end of ento namespace
} // end of clang namespace

#endif // LLVM_CLANG_STATICANALYZER_STRINGSPLIT_H
