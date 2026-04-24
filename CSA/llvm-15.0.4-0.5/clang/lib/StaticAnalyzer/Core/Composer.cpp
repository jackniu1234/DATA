#include "clang/StaticAnalyzer/Core/PathSensitive/Composer.h"
#include "clang/AST/DeclVisitor.h"
#include <functional>
#include <optional>
#include <exception>
#include <regex>

namespace clang {
namespace ento {

std::string getStandardStr(StringRef ss) {
  std::string ret;
  for (auto ch : ss) {
    if (ch != ' ' && ch != '\n')
      ret.push_back(ch);
  }
  return ret;
}

SVal Composer::IdenticalButNotUnknown(SVal S) const {
  if (S.isUnknown())
    return SummaryFailedVal();
  else
    return S;
}

Composer::ComposeFn Composer::dispatchSVal(StringRef name) const {
  ComposeFn retVal = 
    llvm::StringSwitch<ComposeFn>(name)
      .StartsWith("MemRegionVal",
                  &Composer::composeMemRegionVal)
      .StartsWith("ConcreteIntLoc",
                  &Composer::composeConcreteIntLoc)
      .StartsWith("ConcreteIntNonLoc",
                  &Composer::composeConcreteIntNonLoc)
      .StartsWith("SymbolVal",
                  &Composer::composeSymbolVal)
      .StartsWith("LocAsInteger",
                  &Composer::composeLocAsInteger)
      .StartsWith("UnknownVal",
                  &Composer::composeUnknownVal)
      .StartsWith("UndefinedVal",
                  &Composer::composeUndefinedVal)
      .StartsWith("LazyCompoundVal",
                  &Composer::composeLazyCompoundVal)
      .Default(nullptr);
  
  if (!retVal) {
    std::string msg;
    std::string outerName = name.split('[').first.str();
    msg = "dispatchSVal failed: " + outerName;
    throw std::logic_error(msg);
  }

  return retVal;
}

Composer::ComposeFn Composer::dispatchSubRegion(StringRef name) const {
  ComposeFn retVal = 
    llvm::StringSwitch<ComposeFn>(name)
      .StartsWith("SymbolicRegion", 
                  &Composer::composeSymbolicRegion)
      .StartsWith("ElementRegion", 
                  &Composer::composeElementRegion)
      .StartsWith("FieldRegion",
                  &Composer::composeFieldRegion)
      .StartsWith("VarRegion",
                  &Composer::composeVarRegion)
      .StartsWith("StringRegion",
                  &Composer::composeStringRegion)
      .StartsWith("FunctionCodeRegion",
                  &Composer::composeFunctionCodeRegion)            
      .Default(nullptr);
  
  if (!retVal) {
    std::string msg;
    std::string outerName = name.split('[').first.str();
    msg = "dispatchSubRegion failed: " + outerName;
    throw std::logic_error(msg);
  }

  return retVal;
}

Composer::ComposeFn Composer::dispatchSymbol(StringRef name) const {
  ComposeFn retVal = 
    llvm::StringSwitch<ComposeFn>(name)
      .StartsWith("SymbolRegionValue", 
                  &Composer::composeSymbolRegionValue)
      .StartsWith("BinarySymExpr",
                  &Composer::composeBinarySymExpr)
      .StartsWith("SymbolConjured",
                  &Composer::composeSymbolConjured)
      .Default(nullptr);
  
  if (!retVal) {
    std::string msg;
    std::string outerName = name.split('[').first.str();
    msg = "dispatchSymExpr failed: " + outerName;
    throw std::logic_error(msg);
  }

  return retVal;
}

SVal Composer::composeSVal(StringRef name, bool inner) const {
  try {
    ComposeFn func = dispatchSVal(name);
    StringRef param = trimOuterBracket(name);
    return (this->*func)(param);
  }
  catch (const std::logic_error& e) {
    if (inner) {
      throw std::logic_error(e.what());
    }
    else {
      out << e.what() << "\n";
      out << "SVal whole name: " << name.str() << "\n";
      return SummaryFailedVal();
    }
  }
}

SVal Composer::composeSubRegion(StringRef name, bool inner) const {
  try {
    ComposeFn func = dispatchSubRegion(name);
    StringRef param = trimOuterBracket(name);
    return (this->*func)(param);
  }
  catch (const std::logic_error& e) {
    if (inner) {
      throw std::logic_error(e.what());
    }
    else {
      out << e.what() << "\n";
      out << "SubRegion whole name: " << name.str() << "\n";
      return SummaryFailedVal();
    }
  }
}

SVal Composer::composeSymbol(StringRef name, bool inner) const {
  try {
    ComposeFn func = dispatchSymbol(name);
    StringRef param = trimOuterBracket(name);
    return (this->*func)(param); 
  } 
  catch (const std::logic_error& e) {
    if (inner) {
      throw std::logic_error(e.what());
    }
    else {
      out << e.what() << "\n";
      out << "Symbol whole name: " << name.str() << "\n";
      return SummaryFailedVal();
    }
  }
}

SVal Composer::composeMemRegion(StringRef name) const {
  if (name.contains("Space") && !name.count('['))  // one pattern
    return loc::MemRegionVal(composeMemSpace(name));
  else
    return composeSubRegion(name);
}

QualType Composer::makeType(StringRef Name) const {
  std::string leftVal = getStandardStr(Name);
  StringRef name = leftVal;
  
  if (name == "int&") {
    QualType IntTy = Actx.IntTy;
    return Actx.getLValueReferenceType(IntTy);
  }

  if (isFuncPtrType(name)) 
    return makeFuncPtrType(name);

  else if (isArrayType(name)) 
    return makeArrayType(name);
  
  else if (isCommonType(name)) 
    return makeCommonType(name);
  
  else {
    std::string msg;
    msg = "makeType failed because don't match: " + name.str();
    throw std::logic_error(msg);
  }
}

QualType Composer::makeArrayType(StringRef name) const {
  // char [3]
  assert(isArrayType(name));

  size_t pos1 = name.find('[');
  size_t pos2 = name.find(']');

  StringRef length_ss = name.slice(pos1+1, pos2);

  uint64_t length;
  bool has_error = length_ss.getAsInteger(10, length) == 0;
  if (!has_error) {
    StringRef base = name.slice(0, pos1);
    QualType typeStripArray = makeCommonType(base);

    llvm::APInt size{64, length};
    return Actx.getConstantArrayType(typeStripArray, size, nullptr,
                                      ArrayType::Normal, 0);
  }
  else {
    std::string msg;
    msg = "makeArrayType failed: " + name.str();
    throw std::logic_error(msg);  
  }
}

QualType Composer::makeCommonType(StringRef name) const {
  assert(isCommonType(name));

  // int* 与 int *都是合法的写法
  unsigned star_num = name.count('*');
  
  StringRef base_name;
  if (star_num) {
    // basename: 位于*前，且去除尾部空格的子字符串
    size_t pos = name.find('*');
    while (pos != 0 && name[pos-1] == ' ') {
      pos--;
    }
    base_name = name.substr(0, pos);
  }
  else {
    base_name = name;
  }

  QualType T = makeBaseType(base_name);
  while (star_num--) {
    T = Actx.getPointerType(T);
  }
  return T;
}

// 如果isProbing为true，则对name试探性的寻找一下，不会抛异常，返回一个isNull检测为true的QualType
QualType Composer::makeStructType(StringRef name, bool isProbing) const {
  const SmallVectorImpl<Type*>& ptypes = Actx.getTypes();
  for (const auto* ptype : ptypes) {
    if (const RecordType* precord = dyn_cast<RecordType>(ptype)) {
      const RecordDecl* recordDecl = precord->getDecl();
      if (recordDecl && recordDecl->getName() == name)
        return QualType(precord, 0);
    }
    else if (const TypedefType* ptypedef = dyn_cast<TypedefType>(ptype)) {
      const TypedefNameDecl* typedefDecl = ptypedef->getDecl();

      if (typedefDecl->getName() == name) {
        // 此处的模式不一定sound
        return ptypedef->desugar().getDesugaredType(Actx);
      }
    }
  }
  if (!isProbing) {
    std::string msg;
    msg = "makeStructType failed: " + name.str();
    throw std::logic_error(msg);
  }
  else {
    return QualType();
  }
}

QualType Composer::makeFuncPtrType(StringRef name) const {
  // int(*)(int*,int) 进入该函数前，name已经Standard
  // 虽然一个函数指针类型理应从头开始构造，但是如果在AST中没有这个类型的函数指针，构造出来也没用
  assert(isFuncPtrType(name));

  StringRef retStr = name.split('(').first;
  size_t pos1 = name.rfind('(');
  size_t pos2 = name.rfind(')');
  StringRef paramStr = name.substr(pos1+1, pos2-pos1-1);

  const FunctionDecl* targetDecl;
  if (!paramStr.empty()) {  // 有参数
    unsigned param_num = paramStr.count(',') + 1;
    if (param_num > MaxItemNum) {
      std::string msg;
      msg = "makeFuncPtrType failed: " + name.str();
      throw std::logic_error(msg);
    }

    std::vector<StringRef> params = commaSplit(paramStr, param_num);
    assert(params.size() == param_num);
  
    auto finder = FunctionDeclFinder(StringRef("all"), params, param_num, retStr);
    targetDecl = finder(Actx.getTranslationUnitDecl());
  }
  else {  // 无参数
    auto finder = FunctionDeclFinder(StringRef("all"), std::vector<StringRef>(), 0, retStr);
    targetDecl = finder(Actx.getTranslationUnitDecl());
  }

  if (targetDecl) {
    return Actx.getPointerType(targetDecl->getType());
  }
  else {
    std::string msg;
    msg = "makeFuncPtrType failed: " + name.str();
    throw std::logic_error(msg);
  }
}

QualType Composer::makeBaseType(StringRef name) const {  
  static QualType VoidTy = Actx.VoidTy, CharTy = Actx.CharTy, WCharTy = Actx.WCharTy,
                  UnsignedIntTy = Actx.UnsignedIntTy, UnsignedLongTy = Actx.UnsignedLongTy,
                  IntTy = Actx.IntTy, LongTy = Actx.LongTy, ShortTy = Actx.ShortTy, 
                  WIntTy = Actx.WIntTy, LongLongTy = Actx.LongLongTy,
                  Int128Ty = Actx.Int128Ty, BoolTy = Actx.BoolTy,
                  UnsignedShortTy = Actx.UnsignedShortTy, UnsignedLongLongTy = Actx.UnsignedLongLongTy,                  
                  FloatTy = Actx.FloatTy, DoubleTy = Actx.DoubleTy, LongDoubleTy = Actx.LongDoubleTy,
                  SizeTy = Actx.getSizeType();

  if (name.startswith("struct")) {
    // name已经Standard
    StringRef structName = name.drop_front(6);  // 去掉开头的struct
    if (structName.empty()) {
      std::string msg;
      msg = "makeStructType failed: " + name.str();
      throw std::logic_error(msg);
    }
    return makeStructType(structName, false);
  }

  if (name.startswith("const") || name.startswith("volatile"))
    name = removeCVfromStr(name);

  if (name == "int")
    return IntTy;
  else if (name == "unsigned" || name == "unsignedint")
    return UnsignedIntTy;
  else if (name == "char")
    return CharTy;
  else if (name == "long")
    return LongTy;
  else if (name == "short")
    return ShortTy;
  else if (name == "size_t") 
    return SizeTy;
  else if (name == "void")
    return VoidTy;
  else if (name == "unsignedlong")
    return UnsignedLongTy;
  else if (name == "longlong" || name == "longlongint")
    return LongLongTy;
  else if (name == "int128")
    return Int128Ty;
  else if (name == "bool")
    return BoolTy;
  else if (name == "unsignedshort")
    return UnsignedShortTy;
  else if (name == "unsignedlonglong" || name == "unsignedlonglongint")
    return UnsignedLongLongTy;
  else if (name == "float")
    return FloatTy;
  else if (name == "double")
    return DoubleTy;
  else if (name == "longdouble")
    return LongDoubleTy;
  else {
    // 此处对应不以struct开头的结构体，常出现在typedef匿名结构体
    clang::QualType structType = makeStructType(name, true);
    if (!structType.isNull()) {
      return structType;
    }
    else {
      std::string msg;
      msg = "makeBaseType failed: " + name.str();
      throw std::logic_error(msg);
    }
  }
}

SVal Composer::composeSymbolVal(StringRef name) const {
  return composeSymbol(name, true);
}

SVal Composer::composeVarRegion(StringRef name) const {
  if (name.startswith("#argument")) {
    // #argument 0
    std::pair<StringRef, StringRef> pair = name.split(' ');
    unsigned idx;  // 使用unsigned主要是因为CE.getArgSVal的函数原型对应unsigned
    if (pair.second.getAsInteger(10, idx) == 0 && idx < CE.getNumArgs()) {
      return CE.getArgSVal(idx);
    }
    else {
      std::string msg;
      msg = "composeVarRegion failed when compose argument: " + name.str();
      throw std::logic_error(msg);
    }
  }
  else if (CallerReturnVar) {
    return loc::MemRegionVal(MemMgr.getVarRegion(CallerReturnVar, Lctx));
  }
  else { 
    std::string msg;
    msg = "composeVarRegion failed: " + name.str();
    throw std::logic_error(msg);
  }
}

SVal Composer::composeElementRegion(StringRef name) const {
  // SymbolicRegion[UnknownSpaceRegion,SymbolRegionValue[#argument int * p]], ConcreteIntNonLoc[1 S64b], int]
  std::vector<StringRef> vec = commaSplit(name, 3);
  StringRef &base = vec[0], &idx = vec[1], &ty = vec[2];

  // 使用MemRegionManager::getElementRegion API构造ElementRegion，依次构造该API的参数

  // 构造superRegion
  SVal srv = composeSubRegion(base, true);
  const SubRegion* superRegion = dyn_cast_or_null<SubRegion>(srv.getAsRegion()->StripCasts());
  if (!superRegion) {
    std::string msg;
    msg = "composeElementRegion failed when compose superRegion: " + base.str();
    throw std::logic_error(msg);
  }

  // 构造Idx
  SVal Idx = composeSVal(idx, true);
  llvm::Optional<NonLoc> pIdx = Idx.getAs<NonLoc>();
  if (!pIdx) {
    std::string msg;
    msg = "composeElementRegion failed when compose superRegion: " + idx.str();
    throw std::logic_error(msg);
  }

  QualType elementType = makeType(ty);

  const MemRegion* R = MemMgr.getElementRegion(elementType, *pIdx,
                                               superRegion, Actx);
  // R = R->StripCasts();
  return loc::MemRegionVal(R);
}

const FieldDecl* Composer::findFieldDecl(StringRef struct_name,
                                         StringRef field_name) const {
  if (struct_name[0] != '{')
    return FieldDeclFinder(struct_name, field_name)(Actx.getTranslationUnitDecl());
  else
    return FieldDeclFinder2(struct_name, field_name)(Actx.getTranslationUnitDecl());  // 匿名结构体
}

SVal Composer::composeFieldRegion(StringRef name) const {
  // VarRegion[#argument 0],T1 t2
  std::pair<StringRef, StringRef> pair = commaSplit(name);
  
  const SubRegion* superRegion;
  StringRef superRegionName = pair.first;
  SVal retVal = composeSubRegion(superRegionName, true);
  if (llvm::Optional<nonloc::LazyCompoundVal> lcv =
                              retVal.getAs<nonloc::LazyCompoundVal>()) {
    superRegion = lcv->getRegion();
  }
  else if (auto sr = dyn_cast_or_null<SubRegion>(retVal.getAsRegion())) {
    superRegion = sr;
  }
  else {
    std::string msg;
    msg = "composeFieldRegion failed when compose superRegion: " + name.str();
    throw std::logic_error(msg);
  }

  std::pair<StringRef, StringRef> pair2 = pair.second.split(' ');
  StringRef struct_name = pair2.first, field_name = pair2.second;
  const FieldDecl* field = findFieldDecl(struct_name, field_name);
  if (field == nullptr) {
    std::string msg;
    msg = "composeFieldRegion failed when find StructDecl: " + name.str();
    throw std::logic_error(msg);
  }

  const FieldRegion* fieldRegion = MemMgr.getFieldRegion(field, superRegion);
  return loc::MemRegionVal(fieldRegion);
}

const MemSpaceRegion* Composer::composeMemSpace(StringRef name) const {
  if (name.startswith("UnknownSpaceRegion")) 
    return MemMgr.getUnknownRegion();

  else if (name.startswith("HeapSpaceRegion"))
    return MemMgr.getHeapRegion();

  else if (name.startswith("GlobalInternalSpaceRegion"))
    return MemMgr.getGlobalsRegion(MemRegion::GlobalInternalSpaceRegionKind);

  else if (name.startswith("GlobalSystemSpaceRegion"))
    return MemMgr.getGlobalsRegion(MemRegion::GlobalSystemSpaceRegionKind);

  else {
    std::string msg;
    msg = "composeMemSpace failed: " + name.str();
    throw std::logic_error(msg);
  }
}

SVal Composer::composeSymbolicRegion(StringRef name) const {
  // UnknownSpaceRegion,SymbolRegionValue[#argument int * p]
  std::pair<StringRef, StringRef> pair = commaSplit(name);

  SVal retVal = composeSymbol(pair.second, true);
  SymbolRef sym = retVal.getAsSymbol();

  if (sym && !isMallocReturnVal(retVal)) {
    // 此时这个sym是未知的
    const MemSpaceRegion* space = composeMemSpace(pair.first);
    return loc::MemRegionVal(MemMgr.getSymbolicRegion(sym, space));
  }
  else {
    // 这个sym已通过实参代入等方式变成确定的了
    if (const MemRegion* R = retVal.getAsRegion()) {
      // R = R->StripCasts();  // 一个无害的操作
      return loc::MemRegionVal(R);
    }
    else {
      // 暂时不认为一个symbolicRegion可在确定后变成非MemRegion
      std::string msg;
      msg = "composeSymbolicRegion failed: " + name.str();
      throw std::logic_error(msg);
    }
  }
}

SVal Composer::composeMemRegionVal(StringRef name) const {
  // ElementRegion[SymbolicRegion[UnknownSpaceRegion,SymbolRegionValue[#argument int * p]], 
  //               ConcreteIntNonLoc[1 S64b], int]]
  return composeSubRegion(name, true);
}

SVal Composer::composeConcreteInt(StringRef name, bool isNonLoc) const {
  // 6 S64b
  std::pair<StringRef, StringRef> pair = name.split(' ');
  bool has_error = false;

  unsigned bits;
  StringRef bits_ss = removeFirstAndLastCh(pair.second);
  has_error |= bits_ss.getAsInteger(10, bits);

  bool isSigned;
  if (pair.second.count('S'))
    isSigned = true;
  else if (pair.second.count('U'))
    isSigned = false;
  else
    has_error = true;

  uint64_t value;
  has_error |= pair.first.getAsInteger(10, value);

  if (has_error) {
    std::string msg;
    msg = "composeConcreteInt failed: " + name.str();
    throw std::logic_error(msg);
  }

  // 构建SVal可以直接使用构造函数，但是MemRegion和SymExpr应该用MemRegionManager和SvalBuilder
  // return nonloc::ConcreteInt(llvm::APSInt(llvm::APInt(bits, value)));
  QualType T = Actx.getIntTypeForBitwidth(bits, isSigned);
  if (!isNonLoc) {
    T = Actx.getPointerType(T); // 当前设置为int*，似乎此处只要是个指针即可
  }

  return SVB.makeIntVal(value, T);
}

SVal Composer::composeConcreteIntNonLoc(StringRef name) const{
  return composeConcreteInt(name, /*isNonLoc*/true);
}

SVal Composer::composeConcreteIntLoc(StringRef name) const {
  return composeConcreteInt(name, /*isNonLoc*/false);
}

SVal Composer::composeSymbolRegionValue(StringRef name) const {  
 if (name.startswith("#argument")) {
    // #argument 0
    std::pair<StringRef, StringRef> pair = name.split(' ');
    unsigned idx;  // 使用unsigned主要是因为CE.getArgSVal的函数原型对应unsigned
    if (pair.second.getAsInteger(10, idx) == 0 && idx < CE.getNumArgs()) {
      return CE.getArgSVal(idx);
    }
    else {
      std::string msg;
      msg = "composeSymbolRegionValue failed when compose argument: " + name.str();
      throw std::logic_error(msg);
    }
  }
  else if (name.startswith("#store")) {
    // #store ElementRegion[SymbolicRegion[UnknownSpaceRegion,SymbolRegionValue[#argument 0]],ConcreteIntNonLoc[1 S64b],int
    std::pair<StringRef, StringRef> pair1 = commaSplit(name);
    std::pair<StringRef, StringRef> pair2 = pair1.first.split(' ');
    StringRef &type_ss = pair1.second, &region_ss = pair2.second;

    QualType T = makeType(type_ss);
    SVal R = composeSubRegion(region_ss, true);

    llvm::Optional<loc::MemRegionVal> pR = R.getAs<loc::MemRegionVal>();
    if (!pR) {
      std::string msg;
      msg = "composeSymbolRegionValue failed for store: " + name.str();
      throw std::logic_error(msg);
    }

    return State->getSVal(*pR, T);
  }
  else { 
    std::string msg;
    msg = "composeSymbolRegionValue failed: " + name.str();
    throw std::logic_error(msg);
  }
}

SVal Composer::composeOneSide(StringRef name) const {
  // #argument int x | #int 2 S32b
  std::pair<StringRef, StringRef> pair = name.split(' ');
  if (pair.first.startswith("#sym")) {
    return composeSymbol(pair.second, true);
  }
  else if (pair.first.startswith("#int")) {
    return composeConcreteIntNonLoc(pair.second);
  }
  else {
    std::string msg;
    msg = "composeBinarySymExpr failed: " + name.str();
    throw std::logic_error(msg);
  }
}

BinaryOperator::Opcode Composer::composeOpcode(StringRef name) const {
  #define BINARY_OPERATION(Name, Spelling) \ 
      else if (Spelling == name)  \
        return clang::BO_##Name;
  
  if (false) {

  }
  #include "clang/AST/OperationKinds.def"
  else {
    std::string msg;
    msg = "composeBinarySymExpr failed when compose Opcode: " + name.str();
    throw std::logic_error(msg);
  }
}

SVal Composer::composeBinarySymExpr(StringRef name) const {
  // #sym SymbolRegionValue[#argument int x],+,#int 2 S32b
  std::vector<StringRef> vec = commaSplit(name, 4);
  StringRef &lhs = vec[0], &op = vec[1], &rhs = vec[2], &ty = vec[3];

  SVal lhs_val = composeOneSide(lhs);
  SVal rhs_val = composeOneSide(rhs);
  BinaryOperator::Opcode opcode = composeOpcode(op);
  QualType T = makeType(ty);
  
  return SVB.evalBinOp(State, opcode, lhs_val, rhs_val, T);
}

SVal Composer::composeSymbolConjured(StringRef name) const {
  // 4,void*
  std::pair<StringRef, StringRef> pair = commaSplit(name);
  unsigned old_id;
  if (pair.first.getAsInteger(10, old_id) != 0) {
    std::string msg;
    msg = "composeSymbolConjured failed: " + name.str();
    throw std::logic_error(msg);
  }

  QualType T = makeType(pair.second);

  unsigned count = MaxCount + old_id;

  SymbolRef sym = SVB.conjureSymbol(CE.getOriginExpr(), CE.getLocationContext(),
                                    T, count);
  // 需要随后只是通过getAssymbol方法使用symbol
  if (Loc::isLocType(T)) {
    return loc::MemRegionVal(MemMgr.getSymbolicRegion(sym));
  }
  else {
    return nonloc::SymbolVal(sym);
  }
}

SVal Composer::composeLocAsInteger(StringRef name) const {
  std::pair<StringRef, StringRef> pair = commaSplit(name);

  unsigned bits;
  if (pair.second.getAsInteger(10, bits) != 0) {
    std::string msg;
    msg = "composeLocAsInteger failed when compose bits: " + name.str();
    throw std::logic_error(msg);
  }

  StringRef loc_name = pair.first;
  SVal _loc = composeSVal(loc_name, true);

  llvm::Optional<Loc> ploc = _loc.getAs<Loc>();
  if (!ploc) {
    std::string msg;
    msg = "composeLocAsInteger failed when compose Loc: " + name.str();
    throw std::logic_error(msg);
  }
  else {
    return SVB.makeLocAsInteger(*ploc, bits);
  }
}

SVal Composer::composeUnknownVal(StringRef name) const {
  return UnknownVal();
}

SVal Composer::composeUndefinedVal(StringRef name) const {
  return UndefinedVal();
}

SVal Composer::composeFunctionCodeRegion(StringRef Name) const {
  // funcname,3,int,int *,double(变长)
  std::string leftVal = getStandardStr(Name);
  StringRef name = leftVal;

  std::vector<StringRef> vec = commaSplit(name, 3);
  unsigned param_num;

  StringRef fname = vec[0];
  bool has_error = vec[1].getAsInteger(10, param_num);  // 如果此处vec[2]==null，has_error也会set
  if (has_error || param_num > MaxItemNum) {
    std::string msg;
    msg = "composeLocAsInteger failed when compose param nums: " + name.str();
    throw std::logic_error(msg);
  }

  std::vector<StringRef> params;
  if (param_num > 0) {
    params = commaSplit(vec[2], param_num);
    assert(param_num == params.size());
  }
  
  auto finder = FunctionDeclFinder(fname, params, param_num);
  const FunctionDecl* targetDecl = finder(Actx.getTranslationUnitDecl());

  if (targetDecl)
    return loc::MemRegionVal(MemMgr.getFunctionCodeRegion(targetDecl));
  else {
    std::string msg;
    msg = "composeFunctionCodeRegion failed due to no decl found: " + name.str();
    throw std::logic_error(msg);
  }
}

SVal Composer::composeLazyCompoundVal(StringRef name) const {
  SVal memVal = composeSubRegion(name, true);
  const MemRegion* region = memVal.getAsRegion();
  const TypedValueRegion* tvr = dyn_cast_or_null<TypedValueRegion>(region);
  if (tvr && NowState) {
    return SVB.makeLazyCompoundVal(
                    StoreRef(NowState->getStore(),
                             NowState->getStateManager().getStoreManager()),
                    tvr);
  }
  else {
    std::string msg;
    msg = "composeLazyCompoundVal failed due to invalid region: " + name.str();
    throw std::logic_error(msg);
  }
}

SVal Composer::composeStringRegion(StringRef name) const {
  // 123,0,0,char[4]
  std::vector<StringRef> vec = commaSplit(name, 4);
  StringRef str = vec[0];
  unsigned _kind;
  bool isPascal;
  
  bool has_error = 0;
  has_error |= vec[1].getAsInteger(10, _kind);
  has_error |= vec[2].getAsInteger(10, isPascal);

  if (has_error) {
    std::string msg;
    msg = "composeStringRegion failed: " + name.str();
    throw std::logic_error(msg);
  }

  StringLiteral::StringKind kind = (StringLiteral::StringKind)_kind;
  QualType T = makeType(vec[3]);

  StringLiteral* literal = StringLiteral::Create(Actx,
                                                 str, kind, isPascal,
                                                 T, nullptr, 1);
  return loc::MemRegionVal(MemMgr.getStringRegion(literal));
}

bool Composer::isMallocReturnVal(SVal S) const {
  // MemRegionVal[ElementRegion[SymbolicRegion[HeapSpaceRegion,SymbolConjured[2,void *]],ConcreteIntNonLoc[0 S64b],int]]
  if (const MemRegion* R = S.getAsRegion()) {
    R = R->StripCasts();
    if (const SymbolicRegion* symR = dyn_cast<SymbolicRegion>(R))
      if (symR->getMemorySpace() == MemMgr.getHeapRegion() &&
                                 isa<SymbolConjured>(symR->getSymbol()))
        return true;
  }
  return false;
} 

void Composer::composeRange(StringRef ss, std::vector<rangePair> &ranges) const{
  // { [-2147483648, 4], [6, 2147483647] } 0 32
  bool has_error = 0;
  auto pair1 = ss.rsplit(' ');
  auto pair2 = pair1.first.rsplit(' ');
  StringRef &numBits_ss = pair1.second, &unsigned_ss = pair2.second;

  unsigned numBits, isUnsigned;
  if (numBits_ss.getAsInteger(10, numBits) != 0 || unsigned_ss.getAsInteger(10, isUnsigned) != 0)
    has_error = 1;

  // 开始处理range
  std::string leftVal = getStandardStr(pair2.first);
  StringRef range = StringRef(leftVal);
  range = range.slice(1, range.size()-1);  // 去除首尾的大括号

  unsigned count = (range.count(',') + 1) / 2;
  if (count > MaxItemNum) 
    has_error = 1;  // 如果这个range约束中出现了太多的并集，则认为是不能处理的
  
  if (has_error) {
    std::string msg;
    msg = "composeRange failed due to split: " + ss.str();
    throw std::logic_error(msg);
  }

  std::vector<StringRef> range_ss_vec = commaSplit(range, count);

  // 获得形如[-2147483648,4]元组的上下界，并得到对应的APSInt
  for (StringRef item : range_ss_vec) {
    StringRef range_ss = item.slice(1, item.size()-1); // 去除首尾的中括号
    auto tmp = range_ss.split(',');
    StringRef &lowerBound_ss = tmp.first, &upperBound_ss = tmp.second;
    uint64_t lowerBound, upperBound;  // 不支持负数
    // { [1, 18446744073709551615] } 1 64
    has_error |= lowerBound_ss.getAsInteger(10, lowerBound);
    has_error |= upperBound_ss.getAsInteger(10, upperBound);

    if (has_error) {
      std::string msg;
      msg = "composeRange failed when get value: " + ss.str();
      throw std::logic_error(msg);
    }

    rangePair pair;
    pair.first = llvm::APSInt(llvm::APInt(numBits, lowerBound), isUnsigned);
    pair.second = llvm::APSInt(llvm::APInt(numBits, upperBound), isUnsigned);
    
    ranges.push_back(pair);
  }
}
NonLoc Composer::composeLocAsInteger(Loc loc, unsigned bits) const{
  return SVB.makeLocAsInteger(loc,bits);
}

bool Composer::isCommonType(StringRef name) const {
  std::regex pattern(".+\\**"); // 任意字符在前，尾部包含0个或多个*

  if (std::regex_match(name.str(), pattern))
    return true;
  else
    return false;
}

bool Composer::isArrayType(StringRef name) const {
  size_t pos1 = name.find('[');
  size_t pos2 = name.find(']');

  if (pos1 == StringRef::npos || pos2 == StringRef::npos)
    return false;
  
  StringRef length = name.slice(pos1+1, pos2);
  unsigned x;
  if (length.getAsInteger(10, x) != 0)
    return false;
  
  StringRef base = name.substr(0, pos1);
  return isCommonType(base);
}

bool Composer::isFuncPtrType(StringRef name) const {
  if (name.count("(*)") && name.count('(') == 2 && name.count(')') == 2) 
    return true;
  else
    return false;
}

StringRef Composer::removeCVfromStr(StringRef name) const {
  // constvolatileint  已经经过Standard
  while (true) {
    if (name.startswith("const"))
      name = name.drop_front(5);
    else if (name.startswith("volatile"))
      name = name.drop_front(8);
    else 
      return name;
  }
}

bool Composer::ostreamHasError() {
  return out.has_error();
}

} // end of ento namespace
} // end of clang namespace


