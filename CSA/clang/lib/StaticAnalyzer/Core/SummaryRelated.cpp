#include "clang/StaticAnalyzer/Core/PathSensitive/SummaryRelated.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MallocCheckerData.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/JsonSummaryManager.h"
#include "clang/StaticAnalyzer/Core/AnalyzerOptions.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>

namespace clang {
namespace ento {

bool isDigits(const std::string& str){
  for(char c : str){
    if(!std::isdigit(c)){
      return false;
    }
  }
  return true;
}

std::vector<std::string> Reader::getStrings() const {
  std::ifstream is(filename);

  std::vector<std::string> vec;
  std::string line;
  while (std::getline(is, line)) {
    // 在此处去掉输入的首尾空格，提高一定的健壮性
    size_t b = line.find_first_not_of(' ');
    size_t e = line.find_last_not_of(' ');
    line = line.substr(b, e-b+1);
    
    vec.push_back(line);
  }
  return vec;
}

// FIXME: this function will not be used anymore!
bool callEventMatchSummary(const CallEvent& CE, StringRef summaryDir,
                           std::string& path) {
  StringRef calleeName = CE.getCalleeName();
  path = summaryDir.str() + '/' + calleeName.str();
  // llvm::outs() << CE.getCalleeSignature();
  // llvm::outs() << "\n----\n";
  // CE.dumpCalleeSignature();
  if (!llvm::sys::fs::exists(path)) {
    path.clear();  // 设置为空字符串
    return false;
  }
  else {
    return true;
  }

}

bool callEventMatchSummary(const CallEvent& CE, JsonSummaryManager& JSM, JsonSummaryKey& key){
  std::string calleeName = CE.getCalleeName().str();
  std::string calleeSignature = CE.getCalleeSignature();
  key = JsonSummaryKey(calleeName + calleeSignature);
  return JSM.hasSummary(key, calleeName);
}

void doComposeSVal(const Reader& reader, const Composer& composer) {
  for (std::string& ss : reader.getStrings()) {
    StringRef param(ss);
    SVal retVal = composer.composeSVal(param);

    raw_ostream& os = llvm::outs();
    retVal.dumpToStream(os);
    os << '\n';
    retVal.customDumpToStream(os);
    os << '\n';
  }
}

std::vector<StateAndCKSummaryPair>
doComposePaths(const CallEvent& CE,
               const JsonSummary& summary,
               Composer& composer) 
{
  std::vector<StateAndCKSummaryPair> stateAndCKSummaryPairs;

  ProgramStateRef state = CE.getState();
  // process every path
  for(JsonPathSummary pathSummary : summary.getPathSummaries()){
    // pathSummary.dumpToStream(llvm::outs());
    ProgramStateRef temp_state;
    const LocationContext *LCtx = CE.getLocationContext();
    temp_state = state;

    // bind store
    for(auto& store : pathSummary.getStores()){
      // TODO 鲁棒性
      // composeMemRegion同时支持composeMemSpace和composeSubRegion
      SVal storeItemRegion = composer.composeMemRegion(StringRef(store.getItem_Region()));
      SVal storeValue = composer.composeSVal(StringRef(store.getValue()));

      // 出现summaryFailed之后，当前的处理是拒绝这一Store字段的应用；
      // 更严格的处理可以是跳过当前这条path，或者拒绝使用摘要处理当前函数调用
      if (storeItemRegion.isSummaryFailed() 
              || storeValue.isSummaryFailed() 
              || storeItemRegion.getAsRegion() == nullptr) {
        continue;
      }
      
      const MemRegion* R = storeItemRegion.getAsRegion();
      if (isa<GlobalsSpaceRegion>(R)) {
        // 如果对应conservative的分析结果，此处一定是SymbolConjured
        assert(dyn_cast_or_null<SymbolConjured>(storeValue.getAsSymbol()));  
        temp_state = temp_state->invalidateGlobalRegionWhenSummary(
                                        storeItemRegion.castAs<Loc>(), storeValue);
        continue;
      }

      // 此处更本质的问题是R为bindLoc不支持的类型
      // 输出不支持的类型用于调试
      // 目前暂时不考虑这种无法bindLoc的区域的复原，并未发现其对分析精确程度的影响
      // 至多考虑HeapSpace和UnkownSpace这两种，如果已经初始化（如何判断？），则不再bindDefaultInitial
      if(isa<SymbolicRegion>(R)){
        llvm::outs() << "store item error! : ";
        store.dumpToStream(llvm::outs());
        llvm::outs() << "\n";
        storeItemRegion.dumpToStream(llvm::outs());
        llvm::outs() << "\n";
        continue;
      }


      // crash
      temp_state = temp_state->bindLoc(storeItemRegion, storeValue, LCtx);
    }

    if(!pathSummary.getConstraints().empty()){
      // bind constraints
      for(auto& constraint : pathSummary.getConstraints()){
        SVal constraintSymbol = composer.composeSymbol(llvm::StringRef(constraint.getSymbol()));
        if(constraintSymbol.isSummaryFailed()){
          llvm::outs() << "this constraint item: " << constraint.getSymbol() << "deserialize failed!\n";
          continue;
        }
        // nonloc -> nonloc
        Optional<NonLoc> constraintNonLoc = constraintSymbol.getAs<NonLoc>();
        std::vector<rangePair> ranges;
        composer.composeRange(llvm::StringRef(constraint.getRange()),ranges);
        int usedConstraints = 0;
        // loc -> nonloc
        if(!constraintNonLoc){
          Optional<Loc> constraintLoc = constraintSymbol.getAs<Loc>();
          if(!constraintLoc){
            llvm::outs() << "this constraint item: " << constraint.getSymbol() << "is not Loc or NonLoc\n";
            constraintSymbol.customDumpToStream(llvm::outs());
            llvm::outs() << "\n SVal kind is " << constraintSymbol.getRawKind() << "\n";
            continue;
          }
          QualType pointer_type = constraintLoc.getValue().getType(temp_state->getAnalysisManager().getASTContext());
          unsigned bits = temp_state->getAnalysisManager().getASTContext().getTypeSize(pointer_type);
          Loc constraintLocValue = constraintLoc.getValue();
          if(isa<loc::ConcreteInt>(constraintLocValue)){
            // usually 0, means null-pointer
            constraintNonLoc = Optional<NonLoc>(nonloc::ConcreteInt(*(constraintLocValue.getAsInteger())));
          }else{
            constraintNonLoc = Optional<NonLoc>(composer.composeLocAsInteger(constraintLocValue, bits));
          }
          
        }

        for(auto range : ranges){
          // isa<NonLoc>(Val) 仅支持NonLoc类型
          // 是什么导致导出的值还原后并非NonLoc？是反序列化出现了问题？还是需要将Loc转换为NonLoc
          if(constraintNonLoc){
            if(temp_state->assumeInclusiveRange(*constraintNonLoc,range.first,range.second,true)){
              temp_state = temp_state->assumeInclusiveRange(*constraintNonLoc,range.first,range.second,true);
              usedConstraints ++;
            }
          }else{
            llvm::errs() << "should't reach here!";
          }
          
        }
        // 判断是否需要舍弃
        if(usedConstraints == 0){
          temp_state = nullptr;
          break;
        }
      }
    }

    if (temp_state == nullptr)
      continue; // 跳过这个路径
    
    // deserilize checker messages and store to checkerDatasMap; 
    //   checkerDatasMap will store to statesAndCheckerDatasMaps at last
    std::map<std::string, void*> checkerDatasMap;
    for(auto& checkerMessage : pathSummary.getCheckerMessages()){
      CheckerDataComposeFn fn = dispatchCheckerComposer(checkerMessage.getChecker());
      if (fn){
        void* checkerDatas = fn(checkerMessage.getMessages(), composer);
        // char *str = new char[64];
        // strcpy(str, checkerMessage.getChecker().c_str());
        checkerDatasMap[checkerMessage.getChecker()] = checkerDatas;
        llvm::outs() << "compose checker's messages: " << checkerMessage.getChecker() << "\n";
        llvm::outs() << checkerDatasMap["unix.DynamicMemoryModeling"] << "\n";
        llvm::outs() << checkerDatas << "\n";
        for(auto it : checkerDatasMap){
          llvm::outs() << "key: " << it.first << "value: " << it.second << "\n";
        }
      }else{
        llvm::outs() << "unsupported checker's messages: " << checkerMessage.getChecker() << "\n";
      }
    }

    // bind return val
    SVal returnValue;
    switch(pathSummary.getReturnType()){
      case ReturnValueType::CONSTANT :
        returnValue = composer.composeConcreteInt(llvm::StringRef(pathSummary.getReturnValue()));
        temp_state = temp_state->BindExpr(CE.getOriginExpr(), LCtx, returnValue);
        break;

      case ReturnValueType::VARIABLE :
        // 需要考虑上下文的绑定
        composer.setNowState(temp_state);
        returnValue = composer.composeSVal(pathSummary.getReturnValue());
        temp_state = temp_state->BindExpr(CE.getOriginExpr(), LCtx, returnValue);
        break;

      default :
        // void, maybe don't need to process
        break;
    }
    stateAndCKSummaryPairs.emplace_back(temp_state, checkerDatasMap);
  }
  return stateAndCKSummaryPairs;
}

int64_t ElementOffsetToInt(uint64_t offset, uint64_t typeSize){
  int64_t result = 0;
  result = offset / typeSize;
  
  return result;

}

void* doComposeMallocCheckerData(const Reader& reader, const Composer& composer) {
  raw_ostream& os = llvm::outs();

  static MallocCheckerDatas datas;
  for (std::string& ss : reader.getStrings()) {
    StringRef param(ss);
    llvm::Optional<MallocCheckerData> pdata =
                     MallocCheckerData::Deserialize(composer, param);
    if (!pdata) {
      // 当反序列化MallocCheckerData失败时，目前的做法是舍弃这一条记录
      os << "compose Malloc data failed:" << ss << '\n';
      continue;
    }

    datas.push_back(*pdata);
    pdata->dumpToStream(os);
    os << '\n';
  }
  return &datas;
}

void* doComposeMallocCheckerData(const std::vector<std::string>& serializeStrings, const Composer& composer) {
  raw_ostream& os = llvm::outs();

  MallocCheckerDatas* datas = new MallocCheckerDatas;
  for (const std::string& ss : serializeStrings) {
    StringRef param(ss);
    llvm::Optional<MallocCheckerData> pdata =
                     MallocCheckerData::Deserialize(composer, param);
    if (!pdata) {
      // 当反序列化MallocCheckerData失败时，目前的做法是舍弃这一条记录
      os << "compose Malloc data failed:" << ss << '\n';
      continue;
    }
    os << "deserialize data: ";
    datas->push_back(*pdata);
    pdata->dumpToStream(os);
    os << '\n';
  }
  return datas;
}

CheckerDataComposeFn dispatchCheckerComposer(const std::string& name){
  // TODO support more checkers 
  return llvm::StringSwitch<CheckerDataComposeFn>(name)
      .StartsWith("unix.DynamicMemoryModeling",
                  &doComposeMallocCheckerData)
      .Default(nullptr);
}

const VarDecl* getReturnVarDecl(ExprEngine& Eng, const CallEvent& Call) {
  // 只有返回值是RecordType，才需要使用该VarDecl处理返回值中的lazyCompoundVal
  if (!Call.getResultType().getTypePtr()->isRecordType())
    return nullptr;

  llvm::Optional<CFGElement> cfgElem = Eng.getNextCFGElement();
  if (!cfgElem)
    return nullptr;

  llvm::Optional<CFGStmt> cfgStmt = cfgElem->getAs<CFGStmt>();
  if (!cfgStmt)
    return nullptr;

  const Stmt* stmt= cfgStmt->getStmt();

  if (const DeclStmt* declStmt = dyn_cast<DeclStmt>(stmt)) {
    const Decl* varDecl = declStmt->getSingleDecl();
    return dyn_cast_or_null<VarDecl>(varDecl); // 可能为nullptr
  }
  else if (const DeclRefExpr* declRef = dyn_cast<DeclRefExpr>(stmt)) {
    const Decl* varDecl = declRef->getDecl();
    return dyn_cast_or_null<VarDecl>(varDecl);
  }
  else {
    return nullptr;
  }
}

shared_ptr<Composer> makeOneComposer(ExprEngine& Eng, const CallEvent& Call, const ExplodedNode* Pred) {
  
  const VarDecl* varDecl = getReturnVarDecl(Eng, Call);
  
  return shared_ptr<Composer>(
           new Composer{Eng.getContext(), Eng.getSValBuilder(), 
                        Eng.getRegionManager(), Call, Pred->getState(), 
                        Eng.getAnalysisManager().options.maxBlockVisitOnPath,
                        Eng.getLogPath(), Call.getLocationContext(), varDecl}
  );
}

} // end of ento namespace
} // end of clang namespace