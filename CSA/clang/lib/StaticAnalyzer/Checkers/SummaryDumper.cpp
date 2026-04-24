//===----------------------------------------------------------------------===//
//
//  This file defines checker that dump exploded graph information or function summary information.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/Analysis/ProgramPoint.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Store.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/Path.h"
#include <utility>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>

using namespace clang;
using namespace ento;

namespace {
using NodeRef = clang::ento::ExplodedNode *;
using NodePair = std::pair<NodeRef,NodeRef> ;
using NodeTriple = std::pair<NodePair,NodeRef> ;

struct PathInfo {
  NodeRef EdgeNode;
  NodeRef LastNode;
  NodeRef ReturnNode;
  std::vector<NodeRef> ConditionNodes;
};

class SummaryDumper : public Checker< check::EndAnalysis > {
private:
  void printNode(const NodeRef I,llvm::raw_ostream &output) const{

    output << "\"node" << I->getID() << "\": {";
    output << "\"programPoint\": {";
    I->getLocation().printJson(output);
    output << "} ," << "\n";
    output << "\"programState\": {";
    I->getState()->printJson(output,I->getLocationContext(),"",1,false);
    output << "} ," << "\n";
    // pred
    output << "\"precursor\": [";
    if(I -> pred_empty())
      output << "null";
    for(auto ei = I->pred_begin(), ee = I->pred_end(); ei != ee; ei ++){
      output << "\"node" << (*ei)->getID() << "\"";
      if(ei + 1 != ee){
        output << ", ";
      }
    }
    output << "] ," << "\n";
    // succ
    output << "\"successor\": [";
    if(I -> succ_empty())
      output << "null";
    for(auto ei = I->succ_begin(), ee = I->succ_end(); ei != ee; ei ++){
      output << "\"node" << (*ei)->getID() << "\"";
      if(ei + 1 != ee){
        output << ", ";
      }
    }
    output << "]" << "\n";
    output << "}";
  }

  void printMergeNode(const PathInfo &nodes, llvm::raw_ostream &output,ExprEngine &Eng) const{

    NodeRef edgeNode = nodes.EdgeNode;
    NodeRef lastNode = nodes.LastNode;
    NodeRef returnNode = nodes.ReturnNode;
    // debug
    if(!edgeNode){
      output << "error edge Node!\n";
      printNode(lastNode, output);
    }
    assert(edgeNode && lastNode);

    ProgramStateManager &edgeMgr = edgeNode->getState()->getStateManager();
    ProgramStateManager &lastMgr = lastNode->getState()->getStateManager();
    // AnalysisDeclContextManager &aMgr = Eng.getAnalysisDeclContextManager();

    output << "{" << "\n";

    output << "\"id\" :" << edgeNode->getID() << ",\n";
    output << "\"program_point\": {" << "\n";
    edgeNode->getLocation().printJson(output);
    output << "}," << "\n"; 
    output << "\"program_state\": {" << "\n";
  // Print the store. For summaries we don't emit the full store blob —
  // it is often large and not useful for cross-function summaries. Emit
  // a sentinel value "none" instead.
  output << "\"store\": \"none\",\n";
    // Print out the constraints.
    if (!nodes.ConditionNodes.empty()) {
      std::vector<std::string> constraints;
      mergeConstraints(nodes.ConditionNodes, constraints);
      output << "\"constraints\": ";
      if (constraints.empty()) {
        output << "null,\n";
      } else {
        output << '[' << "\n";
        for (auto it = constraints.begin(); it != constraints.end();) {
          output << *it;
          if (++it != constraints.end()) {
            output << ',';
          }
          output << "\n";
        }
        output << "],\n";
      }
    } else {
      edgeMgr.getConstraintManager().customDumpToStream(output, edgeNode->getState());
    }
    // Print out the environment.
    // lastNode->getState()->getEnvironment().printJson(output, lastMgr.getContext(), lastNode->getLocationContext(), "\n", 1, false);
    lastNode->getState()->getEnvironment().customDumpToStream(output, lastMgr.getContext(), lastNode->getLocationContext());
    // return value is constant
    output << "\"const_return_value\": ";
    if(lastNode->getState()->getEnvironment().begin() == lastNode->getState()->getEnvironment().end() && returnNode && ((const ReturnStmt *)(returnNode->getLocation().castAs<StmtPoint>().getStmt()))->getRetValue()){
      SVal returnVal = returnNode->getState()->getSVal(((const ReturnStmt *)(returnNode->getLocation().castAs<StmtPoint>().getStmt()))->getRetValue(), returnNode->getLocationContext());
      output << "\"";
      returnVal.dumpToStream(output);
      output << "\"";
    }else{
      output << "null";
    }
    output << ",\n";
    // Print out the tracked dynamic types.(maybe don't need anymore)
    //printDynamicTypeInfoJson(output, edgeNode->getState(), "\n", 1, false);
    // Print checker-specific data.
    // edgeMgr.getOwningEngine().printJson(output, edgeNode->getState(), edgeNode->getLocationContext(), "\n", 1, false);
    edgeMgr.getOwningEngine().customDumpToStream(output, edgeNode->getState(), edgeNode->getLocationContext());
    output << "}}"; 
  }

  const void mergeConstraints(const std::vector<NodeRef>& conditionNodes, std::vector<std::string>& constraints) const {
    // We want later constraints (from later nodes) to override earlier ones when
    // they reference the same "symbol". To do that, parse each constraint JSON
    // item, extract the symbol (if any) and keep a map symbol->item where later
    // occurrences overwrite earlier ones. For items without a symbol, keep a
    // unique list.

    std::unordered_map<std::string, std::string> symMap; // symbol -> item
    std::vector<std::string> symOrder; // ordering of symbols (last-seen order)
    std::unordered_set<std::string> extraSeen;
    std::vector<std::string> extras;

    auto extractSymbol = [&](const std::string &item) -> std::string {
      // Find "symbol" key and extract the quoted string value that follows.
      size_t keyPos = item.find("\"symbol\"");
      if (keyPos == std::string::npos)
        return std::string();
      size_t colon = item.find(':', keyPos);
      if (colon == std::string::npos)
        return std::string();
      // find first '"' after colon
      size_t firstQuote = item.find('"', colon);
      if (firstQuote == std::string::npos)
        return std::string();
      size_t secondQuote = item.find('"', firstQuote + 1);
      if (secondQuote == std::string::npos)
        return std::string();
      return item.substr(firstQuote + 1, secondQuote - firstQuote - 1);
    };

    auto normalizeRangeInItem = [&](std::string &item) {
      // Find the "range" field and clean its string value by replacing a
      // comma followed by a newline (or CRLF) with a single space and by
      // removing any internal newlines. This preserves commas inside
      // bracketed lists (e.g. "[0, 0]") because those are not followed by
      // a newline.
      size_t keyPos = item.find("\"range\"");
      if (keyPos == std::string::npos)
        return;
      size_t colon = item.find(':', keyPos);
      if (colon == std::string::npos)
        return;
      // Find the start of the value (skip whitespace)
      size_t vpos = colon + 1;
      while (vpos < item.size() && isspace((unsigned char)item[vpos]))
        ++vpos;

      bool quoted = false;
      size_t valStart = vpos;
      size_t valEnd = std::string::npos;
      if (vpos < item.size() && item[vpos] == '"') {
        quoted = true;
        valStart = vpos + 1;
        valEnd = item.find('"', valStart);
        if (valEnd == std::string::npos)
          return; // unterminated quote; bail out
      } else {
        // Unquoted value: find next comma or closing brace
        valStart = vpos;
        size_t comma = item.find(',', valStart);
        size_t brace = item.find('}', valStart);
        if (comma == std::string::npos && brace == std::string::npos)
          valEnd = item.size();
        else if (comma == std::string::npos)
          valEnd = brace;
        else if (brace == std::string::npos)
          valEnd = comma;
        else
          valEnd = std::min(comma, brace);
        // Trim trailing whitespace from valEnd
        while (valEnd > valStart && isspace((unsigned char)item[valEnd - 1]))
          --valEnd;
      }

      std::string val = item.substr(valStart, valEnd - valStart);

      // Replace the pattern "},\r\n" (CRLF) or "},\n" (LF) or "},\r" (CR)
      // with a single "} " so that a trailing comma + newline is converted
      // into a single space. Use the correct length for the replaced
      // substrings when calling string::replace.
      size_t p = 0;
      while ((p = val.find("},\r\n", p)) != std::string::npos) {
        val.replace(p, 4, "} ");
        p += 2; // advance to avoid re-checking the inserted space
      }
      p = 0;
      while ((p = val.find("},\n", p)) != std::string::npos) {
        val.replace(p, 3, "} ");
        p += 2;
      }
      // Also handle plain CR and cases like "},\n ".
      p = 0;
      while ((p = val.find("},\r", p)) != std::string::npos) {
        val.replace(p, 3, "} ");
        p += 2;
      }

      // Remove any remaining newlines inside the value and replace with space.
      for (char &c : val) {
        if (c == '\n' || c == '\r')
          c = ' ';
      }

      // Collapse any repeated spaces that may have been introduced.
      std::string out;
      out.reserve(val.size());
      bool lastSpace = false;
      for (char c : val) {
        if (c == ' ') {
          if (!lastSpace) {
            out.push_back(c);
            lastSpace = true;
          }
        } else {
          out.push_back(c);
          lastSpace = false;
        }
      }

      // Recompose the item with the cleaned range value. Preserve quotes
      if (quoted) {
        item = item.substr(0, valStart) + out + item.substr(valEnd);
      } else {
        // valStart/valEnd pointed to unquoted region; replace that region
        item = item.substr(0, valStart) + out + item.substr(valEnd);
      }
    };

    for (NodeRef node : conditionNodes) {
      if (!node) continue;
      std::string Buf;
      llvm::raw_string_ostream tmpOut(Buf);
      ProgramStateManager &mgr = node->getState()->getStateManager();
      mgr.getConstraintManager().customDumpToStream(tmpOut, node->getState());
      tmpOut.flush();
      size_t lb = Buf.find('[');
      size_t rb = Buf.rfind(']');
      if (lb == std::string::npos || rb == std::string::npos || rb <= lb) {
        continue;
      }
      std::string inner = Buf.substr(lb + 1, rb - lb - 1);
      size_t pos = 0;
      while (pos < inner.size()) {
        // Find the next item which should be a JSON object starting with '{'.
        size_t start = inner.find('{', pos);
        if (start == std::string::npos) break;
        // Find the matching closing '}' by counting nested braces so that
        // inner '}' characters (for example those inside the "range" value)
        // don't terminate the item early.
        size_t idx = start;
        int depth = 0;
        for (; idx < inner.size(); ++idx) {
          if (inner[idx] == '{')
            ++depth;
          else if (inner[idx] == '}') {
            --depth;
            if (depth == 0)
              break;
          }
        }
        if (idx >= inner.size())
          break; // unterminated item
        std::string item = inner.substr(start, idx - start + 1);
        // Trim leading/trailing whitespace and commas
        size_t start_non = item.find_first_not_of("\n\r \t,");
        if (start_non != std::string::npos)
          item = item.substr(start_non);
        else
          item.clear();
        size_t end_non = item.find_last_not_of("\n\r \t,");
        if (end_non != std::string::npos)
          item = item.substr(0, end_non + 1);
        else
          item.clear();

        if (item.empty()) {
          pos = idx + 1;
          continue;
        }

        // Normalize the "range" field formatting inside the item so that
        // commas/newlines embedded in the range value are converted to the
        // desired single-space form (e.g. "{ [0, 0] },\n1 64" ->
        // "{ [0, 0] } 1 64").
        normalizeRangeInItem(item);

        std::string sym = extractSymbol(item);
        if (!sym.empty()) {
          // If symbol already seen earlier, remove it from symOrder so we can
          // place it at the end (last-seen wins). Then overwrite map entry.
          if (!symMap.count(sym)) {
            symOrder.push_back(sym);
          } else {
            // move existing symbol to end
            auto it = std::find(symOrder.begin(), symOrder.end(), sym);
            if (it != symOrder.end()) {
              symOrder.erase(it);
              symOrder.push_back(sym);
            }
          }
          symMap[sym] = item; // overwrite previous (later nodes win)
        } else {
          // No symbol field: keep unique by full item text
          if (extraSeen.insert(item).second) {
            extras.push_back(item);
          }
        }

        // Advance pos to the character after the end of this item so the
        // next iteration continues searching from there.
        pos = idx + 1;
      }
    }

    // Build final constraints vector: first the symbol-mapped items in their last-seen order,
    // then any extras (unique items without symbol).
    constraints.clear();
    for (const std::string &sym : symOrder) {
      constraints.push_back(symMap[sym]);
    }
    for (const std::string &ex : extras) {
      constraints.push_back(ex);
    }
  }

  void backtraceClear(std::stack<std::pair<NodeRef, std::vector<NodeRef>>> &nodes, std::stack<NodeRef> &path, const ExplodedGraph &G,std::map<std::pair<int64_t,int64_t>,int> &loop_map) const{
    if(nodes.empty()){
      return;
    }
    // parent untill
    NodeRef next_node = nodes.top().first;
    int found_backtrace_point = 0;
    for(auto ei = next_node->pred_begin(), ee = next_node->pred_end(); ei != ee; ei ++){
        if((*ei)->getID() == path.top()->getID()){
          found_backtrace_point = 1;
        }
    }
    while(!found_backtrace_point){
      loop_map[{path.top()->getState()->getID(),path.top()->getID()}] --;
      path.pop();
      if(path.empty()){
        break;
      }
      for(auto ei = next_node->pred_begin(), ee = next_node->pred_end(); ei != ee; ei ++){
        if((*ei)->getID() == path.top()->getID()){
          found_backtrace_point = 1;
        }
      }
    }
  }

  void DumpSummary(const ExplodedGraph &G,ExprEngine &Eng) const{
    // llvm::raw_ostream &output = llvm::outs();

    std::string Buf;
    llvm::raw_string_ostream output(Buf);

    // dfs
    std::stack<std::pair<NodeRef, std::vector<NodeRef>>> nodes;
    std::vector<PathInfo> mergeNodes;
    int num = 0;
    nodes.push(std::make_pair(*(G.roots_begin()), std::vector<NodeRef>()));
    NodeRef returnNode = nullptr;
    NodeRef lastNode = nullptr;
    NodeRef edgeNode = nullptr;
    NodeRef functionNode = nullptr;
    output << "{\n" ;

    std::map<std::pair<int64_t,int64_t>,int> loop_map;
    std::stack<NodeRef> temp_path;

    while(!nodes.empty()){
      auto frame = nodes.top();
      nodes.pop();
      NodeRef node = frame.first;
      std::vector<NodeRef> conditionNodes = frame.second;
      loop_map[{node->getState()->getID(),node->getID()}] ++;
      temp_path.push(node);
      if(loop_map[{node->getState()->getID(),node->getID()}] > 1){
        // backtrace clear
        backtraceClear(nodes,temp_path,G,loop_map);
        continue;
      }
      clang::ProgramPoint pp = node->getLocation();
      const Stmt *s = NULL;
      if((pp.getKind() > 2 && pp.getKind() < 7)){
        s = pp.castAs<StmtPoint>().getStmt();
      }else {
        s = NULL;
      }

      // is_sink (drop this path)
      if(node->isSink()){
        // drop any found node!
        returnNode = nullptr;
        lastNode = nullptr;
        edgeNode = nullptr;
        //loop_map.clear();
        backtraceClear(nodes,temp_path,G,loop_map);
        continue;
      }
      
      // return stmt (get node info)
      if(s && strcmp(s->getStmtClassName(),"ReturnStmt") == 0){
        returnNode = node;
      }
      if (pp.getKind() == ProgramPoint::BlockEdgeKind){
        // dst cfg block is 0
        if(pp.castAs<BlockEdge>().getDst()->BlockID == 0){
          edgeNode = node;
        }
      }else if(pp.getKind() == ProgramPoint::CallExitBeginKind){
        // clear returnNode
        returnNode = NULL;
      }

      // // last node (get return value)
      if(node->succ_empty()){
        lastNode = node;
        functionNode = node;
        NodePair np(edgeNode,lastNode);
        NodeTriple nt(np,returnNode);
        if(s && strcmp(s->getStmtClassName(),"CompoundStmt") == 0){
          // real last node
          PathInfo pi;
          pi.EdgeNode = edgeNode;
          pi.LastNode = lastNode;
          pi.ReturnNode = returnNode;
          pi.ConditionNodes = conditionNodes;
          mergeNodes.push_back(pi);
          num ++;
        }
        //loop_map.clear();
        backtraceClear(nodes,temp_path,G,loop_map);
        returnNode = NULL;
        lastNode = NULL;
        edgeNode = NULL;
      }

      // add succ
      bool isConditionTerminator = false;
      if (pp.getKind() == ProgramPoint::BlockEdgeKind) {
        const BlockEdge &BE = pp.castAs<BlockEdge>();
        const Stmt *T = BE.getSrc()->getTerminatorStmt();
        // 需要这样判断吗？
        if (T && !isa<SwitchStmt>(T) && !isa<IndirectGotoStmt>(T)) {
          isConditionTerminator = true;
        }
      }
      for(auto ei = node->succ_begin(), ee = node->succ_end(); ei != ee; ei ++){
        NodeRef succ = *ei;
        std::vector<NodeRef> succConditionNodes = conditionNodes;
        if (isConditionTerminator) {
          succConditionNodes.push_back(node);
        }
        nodes.push(std::make_pair(succ, std::move(succConditionNodes)));
      }
    }
    // maybe all nodes are dropped!
    if (!functionNode){
      functionNode = *(G.roots_begin());
    }
    bool EnableMerge = Eng.getAnalysisManager().options.EnableMerge;
  // default CSA merge
  mergeNodes = doCSAMerge(mergeNodes, Eng);
  // After merging the number of merge nodes may have changed; update num
  num = static_cast<int>(mergeNodes.size());
    if (EnableMerge) {
      // more strong path merge

    }
    const Decl* D = functionNode->getLocationContext()->getDecl();
    if (const FunctionDecl *FD = dyn_cast<FunctionDecl>(D)) {
      output << "\"function_name\" : ";
      output << "\"" << FD->getNameAsString() << "\",\n";
      output << "\"function_signature\" : ";
      QualType QT = FD->getType();
      output << "\"" << QT.getAsString() << "\",\n";
    }else {
      output << "\"function_name\" : null,\n";
      output << "\"function_signature\" : null,\n";
    }

    output << "\"path_summary\" : [\n";
    for(int i = 0; i < num - 1;i++){
      printMergeNode(mergeNodes[i], output,Eng);
      output << ",\n";
    }
    if(num > 0){
      printMergeNode(mergeNodes[num - 1], output,Eng);
      output << "\n";
    }
    output << "]\n";

    output << "}\n";

    // output to std out for debug
    llvm::outs() << output.str();
    // just for test, so write simply.
    // Use a dedicated export directory if configured; otherwise fall back
    // to the SummaryDir which is used for reading summaries.
    std::string dirPath = Eng.getAnalysisManager().options.SummaryExportDir.str();
    if (dirPath.empty())
      dirPath = Eng.getAnalysisManager().options.SummaryDir.str();
    std::string filePath = dirPath + "/" + dyn_cast<FunctionDecl>(D)->getNameAsString() + ".json";
    std::error_code ec;
    llvm::raw_fd_ostream  jsonFile(StringRef(filePath), ec, llvm::sys::fs::CD_CreateAlways);
    jsonFile << output.str();

  }

  std::vector<PathInfo> doCSAMerge(const std::vector<PathInfo>& mergeNodes, ExprEngine &Eng) const {
    // Simple CSA-style merge approximation:
    // If two PathInfo entries have the same LastNode (same program point and state),
    // merge them by keeping the first entry and discarding the duplicate. To be
    // conservative, clear the ConditionNodes of the kept entry so it represents
    // a sound over-approximation of both paths.
    if (mergeNodes.empty())
      return mergeNodes;

  std::vector<PathInfo> Result;
    // First pass: count occurrences of each LastNode ID.
    std::unordered_map<int64_t, int> Occur;
    for (const PathInfo &PI : mergeNodes) {
      if (!PI.LastNode) continue;
      Occur[PI.LastNode->getID()]++;
    }

    // Second pass: keep entries. If a LastNode occurs more than once,
    // we clear the ConditionNodes for the first kept entry and skip later
    // duplicates. If it occurs only once, keep it unchanged.
    std::unordered_map<int64_t, bool> Kept;
    Result.reserve(mergeNodes.size());
    for (const PathInfo &PI : mergeNodes) {
      if (!PI.LastNode) {
        Result.push_back(PI);
        continue;
      }
      int64_t id = PI.LastNode->getID();
      int cnt = Occur[id];
      if (cnt <= 1) {
        // unique LastNode: keep original entry (including ConditionNodes)
        Result.push_back(PI);
        continue;
      }
      // cnt > 1 : need to merge duplicates
      if (!Kept[id]) {
        // first occurrence: keep but clear ConditionNodes
        PathInfo NewPI = PI;
        NewPI.ConditionNodes.clear();
        Result.push_back(std::move(NewPI));
        Kept[id] = true;
      } else {
        // subsequent duplicate: skip
      }
    }

    return Result;
  }
  
  void DumpExplodedGraph(const ExplodedGraph &G) const{
    
    // std out for debug
    llvm::raw_ostream &output = llvm::outs();

    output << "\"nodes\": [" <<"\n";

    for(auto I = G.nodes_begin(), E = G.nodes_end(); I != E;){
      //ProgramStateManager &Mgr = getStateManager();
      //output << "\"node\": {";

      output << "\"node" << I->getID() << ":\" {";
      output << "\"programPoint\": {";
      I->getLocation().printJson(output);
      output << "} ," << "\n";
  output << "\"programState\": {\"store\": \"none\"} ," << "\n";
      // pred
      output << "\"precursor\": [";
      if(I -> pred_empty())
        output << "null";
      for(auto ei = I->pred_begin(), ee = I->pred_end(); ei != ee; ei ++){
        output << "\"node" << (*ei)->getID() << "\"";
        if(ei + 1 != ee){
          output << ", ";
        }
      }
      output << "] ," << "\n";
      // succ
      output << "\"successor\": [";
      if(I -> succ_empty())
        output << "null";
      for(auto ei = I->succ_begin(), ee = I->succ_end(); ei != ee; ei ++){
        output << "\"node" << (*ei)->getID() << "\"";
        if(ei + 1 != ee){
          output << ", ";
        }
      }
      output << "]" << "\n";
      output << "}";
      if(++I != E){
        output << " ,";
      }
      output << "\n";
    }
    output << "]" << "\n";
  }
public:
  SummaryDumper() {}
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &B,ExprEngine &Eng) const{

    //DumpExplodedGraph(G);
    DumpSummary(G, Eng);
  }
};
}

void ento::registerSummaryDumper(CheckerManager &mgr) {
  mgr.registerChecker<SummaryDumper>();
}

bool ento::shouldRegisterSummaryDumper(const CheckerManager &mgr) {
  return true;
}
