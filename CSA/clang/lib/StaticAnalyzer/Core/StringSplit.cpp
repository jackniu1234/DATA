#include "clang/StaticAnalyzer/Core/PathSensitive/StringSplit.h"
#include "llvm/Support/raw_ostream.h"

namespace clang {
namespace ento {

std::vector<StringRef> commaSplit(StringRef ss, unsigned num, const unsigned MaxNum) {
  // input constraints
  assert(num > 0 && num <= MaxNum);

  if (num == 1)
    return {ss};

  size_t arr[MaxNum+1];
  arr[0] = ~0;  // trick  

  unsigned level = 0, real_num = 1;
  for (size_t i = 0; i < ss.size(); i++) {
    if (ss[i] == ',' && level == 0) {
      arr[real_num++] = i;
      if (real_num == num)
        break;
    }
    else if (ss[i] == ']')
      level--;
    else if (ss[i] == '[') 
      level++;
  }
  
  std::vector<StringRef> retVal;
  arr[real_num] = StringRef::npos;
  for (size_t i = 0; i < real_num; i++) {
    retVal.push_back(ss.slice(arr[i] + 1, arr[i + 1]));
  }
  while (real_num < num) {
    retVal.push_back(StringRef());
    real_num++;
  }
  return retVal;
}

std::pair<StringRef, StringRef> commaSplit(StringRef ss) {
  unsigned level = 0;
  for (size_t i = 0; i < ss.size(); i++) {
    if (ss[i] == ',' && level == 0)
      return std::make_pair(ss.slice(0, i), ss.slice(i + 1, StringRef::npos));
    else if (ss[i] == ']')
      level--;
    else if (ss[i] == '[') 
      level++;
  }
  return std::make_pair(ss, StringRef());
}

StringRef trimHeadAndTail(StringRef ss, StringRef head,
                                        StringRef tail)  {
  // ConcreteIntNonLoc[1 S64b] -> 1 S64 b
  StringRef tmp = ss.ltrim(head);
  return tmp.rtrim(tail);
}

StringRef trimOuterBracket(StringRef ss) {
  size_t pos = ss.find('[');
  if (pos == StringRef::npos || ss.back() != ']') {
    std::string msg;
    if (ss.back() == ' ') 
      msg = "trimOuterBracket failed due to extra last space: " + ss.str();
    else 
      msg = "trimOuterBracket failed: " + ss.str();

    throw std::logic_error(msg);
  }
  StringRef tmp = ss.substr(pos + 1, ss.size()-pos-2);
  return tmp;
}

StringRef removeFirstAndLastCh(StringRef ss) {
    return ss.slice(1, ss.size()-1);
}

} // end of ento namespace
} // end of clang namespace