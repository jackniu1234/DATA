#include "clang/AST/ASTContext.h"
#include "llvm/ADT/StringRef.h"
#include "clang/AST/DeclVisitor.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/StringSplit.h"
#include <vector>

using namespace clang;
using namespace ento;

namespace clang {
namespace ento {

// 去除一个字符串中的所有的空格, 避免char *与char*不等价的情况
std::string getStandardStr(StringRef ss);

class FunctionDeclFinder :
        public ConstDeclVisitor<FunctionDeclFinder, bool> {
private:
  const FunctionDecl* target = nullptr;
  StringRef fname; // all 为通配符，可匹配所有函数
  std::vector<StringRef> params;  // 匹配目标
  unsigned param_num;
  StringRef ret;

public: 
  bool VisitFunctionDecl(const FunctionDecl* Decl) {
    bool name_match = (Decl->getName() == fname) || (fname == "all");

    StringRef decl_ret = getStandardStr(Decl->getReturnType().getAsString());
    bool ret_match = (ret.empty()) || (ret == decl_ret);
    
    if (name_match && ret_match && Decl->getNumParams() == param_num) {
      for (size_t i = 0; i < param_num; i++) {
        auto tmp = Decl->getParamDecl(i)->getType();
        std::string decl_param = getStandardStr(tmp.getAsString());
        if (decl_param != params[i].str())
          return false;
      }
      target = Decl;
      return true;
    }
    else 
      return false;
  }

  bool VisitTranslationUnitDecl(const TranslationUnitDecl* Decl) {
    for (const auto* D : Decl->decls()) {
    if (Visit(D))
        return true;
    }
    return false;
  }

  // 要求_params数组的每一项都是getStandardStr()处理后的
  FunctionDeclFinder(StringRef _fname, std::vector<StringRef> _params, unsigned _param_num, StringRef _ret)
          : fname(_fname), params(_params), param_num(_param_num), ret(_ret) {}
  FunctionDeclFinder(StringRef _fname, std::vector<StringRef> _params, unsigned _param_num)
          : fname(_fname), params(_params), param_num(_param_num) {}

  const FunctionDecl* operator()(const TranslationUnitDecl* Decl) {
    VisitTranslationUnitDecl(Decl);
    return target;
  }
};

class FieldDeclFinder : public ConstDeclVisitor<FieldDeclFinder, bool> {
  
private: 
  const FieldDecl* target = nullptr;
  StringRef struct_name, field_name;

public:
  bool VisitRecordDecl(const RecordDecl* Decl) {
    if (Decl->getName() == struct_name)
      for (const auto* field : Decl->fields())
        if (field->getName() == field_name)
          if (const FieldDecl* decl = dyn_cast<FieldDecl>(field)) {
            target = decl;
            return true;
          } 
    
    return false;
  }
  bool VisitTranslationUnitDecl(const TranslationUnitDecl* Decl) {
    for (const auto* D : Decl->decls()) {
      if (Visit(D))
        return true;
    }
    return false;
  }
  
public:
  FieldDeclFinder(StringRef _struct_name, StringRef _field_name)
    : struct_name(_struct_name), field_name(_field_name) {}

  const FieldDecl* operator()(const TranslationUnitDecl* Decl) {
    VisitTranslationUnitDecl(Decl);
    return target;
  }
};

// used for field of a anoymous struct
class FieldDeclFinder2 : public ConstDeclVisitor<FieldDeclFinder2, bool> {
  
private: 
  const FieldDecl* target = nullptr;
  std::vector<StringRef> fields;
  StringRef field_name;

public:
  bool VisitRecordDecl(const RecordDecl* Decl) {
    if (Decl->getName().empty()) {
      const FieldDecl* potential_target = nullptr;

      size_t i = 0;
      for (auto it = Decl->field_begin(); it != Decl->field_end(); ++it) {
        if (it->getName() != fields[i++])
          return false;

        if (it->getName() == field_name)
          potential_target = *it;
      }
      // 如果fields数目相同，并且名字都匹配，并且找到了field_name
      if (i == fields.size() && potential_target) {
        target = potential_target;
        return true;
      }
    }
    return false;
  }
  bool VisitTranslationUnitDecl(const TranslationUnitDecl* Decl) {
    for (const auto* D : Decl->decls()) {
      if (Visit(D))
        return true;
    }
    return false;
  }
  
public:
  FieldDeclFinder2(StringRef Fields, StringRef FieldName) : field_name(FieldName) {
    // Fields: {a,b}
    Fields = removeFirstAndLastCh(Fields);
    size_t num = Fields.count(',') + 1;
    fields = commaSplit(Fields, num, 100); 
  }

  const FieldDecl* operator()(const TranslationUnitDecl* Decl) {
    VisitTranslationUnitDecl(Decl);
    return target;
  }
};


} // end of ento namespace
} // end of clang namespace