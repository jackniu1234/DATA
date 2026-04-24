#include "clang/StaticAnalyzer/Core/PathSensitive/JsonSummaryManager.h"
#include "rapidjson/document.h"
#include <fstream>
#include <dirent.h>
#include <memory.h>
#include <sstream>
#include <cctype>
#include <algorithm>

namespace clang{
namespace ento{

void JsonPathSummary::addStore(const JsonStore& store){
    this->stores.push_back(store);
}

void JsonPathSummary::addConstraints(const JsonConstraint& constraint){
    this->constraints.push_back(constraint);
}

void JsonPathSummary::addCheckerMessage(const JsonCheckerMessage& checkerMessage){
    this->checkerMessages.push_back(checkerMessage);
}

void JsonPathSummary::setReturnValue(const std::string& returnValue, const ReturnValueType returnType){
    this->returnType = returnType;
    this->returnValue = returnValue;
}

void JsonPathSummary::dropDeadStores(const std::string& localInfo){
    std::vector<JsonStore> pureStores;
    for(auto& store : this->stores){
        const std::string& tmp = store.getItem_Region();
        if(tmp.find("#local") == tmp.npos 
           || tmp.find(localInfo) != tmp.npos){
            pureStores.push_back(std::move(store));
        }
    }
    this->stores = pureStores;
}

void JsonPathSummary::dropDeadStores(){
    std::vector<JsonStore> pureStores;
    for(auto& store : this->stores){
        const std::string& tmp = store.getItem_Region();
        if(tmp.find("#local") == tmp.npos){
            pureStores.push_back(std::move(store));
        }
    }
    this->stores = pureStores;
}

std::vector<JsonStore> JsonPathSummary::getStores() const{
    return this->stores;
}

std::vector<JsonConstraint> JsonPathSummary::getConstraints() const{
    return this->constraints;
}

std::vector<JsonCheckerMessage> JsonPathSummary::getCheckerMessages() const{
    return this->checkerMessages;
}

std::string JsonPathSummary::getReturnValue() const{
    return this->returnValue;
}

ReturnValueType JsonPathSummary::getReturnType() const{
    return this->returnType;
}

void JsonSummary::setSummaryKey(const JsonSummaryKey& summaryKey){
    this->summaryKey = summaryKey;
}
void JsonSummary::addPathSummary(const JsonPathSummary& pathSummary){
    this->pathSummaries.push_back(pathSummary);
}

JsonSummaryKey JsonSummary::getKey() const{
    return this->summaryKey;
}

std::vector<JsonPathSummary> JsonSummary::getPathSummaries() const{
    return this->pathSummaries;
}

void JsonSummaryManager::getFileLists(const std::string& dirPath, std::vector<std::string> &lists){
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir (dirPath.c_str())) != NULL) {
        while ((ent = readdir (dir)) != NULL) {
            if (ent->d_name == nullptr || ent->d_type == DT_DIR){//It's dir
               // do nothing
                continue;
            }else {
                std::string name = ent->d_name;
                std::string imgdir = dirPath +"/"+ name;
                std::string filePath = imgdir.c_str();
                llvm::outs() << "adding to list: " << imgdir << "\n";
                lists.push_back(filePath);
            }
        closedir (dir);
        }
    }else{
        llvm::outs() << "Could not open dir: " << dirPath << ", load summaries error!\n";
    }
}

void JsonSummaryManager::loadSummaries(std::string dirPath){
    // If using a database, we don't need to pre-scan files.
    if (this->databaseEnable)
        return;

    // Instead of eagerly parsing every JSON file, build a mapping from
    // function name -> candidate files. We will lazily parse a file only
    // when a call with that function name is encountered.
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir (dirPath.c_str())) != NULL) {
        while ((ent = readdir (dir)) != NULL) {
            if (ent->d_name == nullptr || ent->d_type == DT_DIR) {
                continue;
            } else {
                std::string name = ent->d_name;
                if (name.find(".json") == std::string::npos)
                    continue;
                std::string imgdir = dirPath + "/" + name;
                llvm::outs() << "adding to list: " << imgdir << "\n";

                // extract base filename without extension -> treat as function name
                std::string base = name;
                size_t pos = base.find_last_of('.');
                if (pos != std::string::npos)
                    base = base.substr(0, pos);

                // record candidate file for this function name
                this->nameToFiles[base].push_back(imgdir);
            }
        }
        closedir(dir);
    } else {
        llvm::outs() << "Could not open dir: " << dirPath << ", load summaries error!\n";
    }
}

// Helper: parse a single json summary file into outSummary. Returns true on success.
bool JsonSummaryManager::parseSummaryFile(const std::string &filePath, JsonSummary &outSummary){
    std::ifstream ifs(filePath);
    if (!ifs.is_open()){
        llvm::errs() << "Could not open file: " << filePath << ", load summary error!\n";
        return false;
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    rapidjson::Document d;
    d.Parse(buffer.str().c_str());
    if(!d.IsObject()||!d.HasMember("function_name") || !d.HasMember("function_signature")){
        return false;
    }
    rapidjson::Value &function_name = d["function_name"];
    rapidjson::Value &function_signature = d["function_signature"];
    JsonSummaryKey key(std::string(function_name.GetString()) + std::string(function_signature.GetString()));
    JsonSummary summary(key);
    if(!d.HasMember("path_summary")){
        return false;
    }
    rapidjson::Value &path_summaries = d["path_summary"];
    if(path_summaries.Empty()){
        return false;
    }
    for (rapidjson::SizeType i = 0; i < path_summaries.Size(); i++){
        if(!path_summaries[i].HasMember("program_state") || path_summaries[i]["program_state"].IsNull()){
            continue;
        }
        rapidjson::Value &program_state = path_summaries[i]["program_state"];
        JsonPathSummary pathSummary;
        if(program_state.HasMember("store") && !program_state["store"].IsNull()){
            rapidjson::Value &stores = program_state["store"];
            for (rapidjson::SizeType j = 0; j < stores.Size(); j++){
                JsonStore tmpStore;
                if(stores[j].IsNull()){
                    continue;
                }
                tmpStore.setItem_Region(stores[j]["item_region"].GetString());
                tmpStore.setValue(stores[j]["value"].GetString());
                pathSummary.addStore(tmpStore);
            }
        }
        if(program_state.HasMember("constraints") && !program_state["constraints"].IsNull()){
            rapidjson::Value &constraints = program_state["constraints"];
            for (rapidjson::SizeType j = 0; j < constraints.Size(); j++){
                JsonConstraint tmpConstraint;
                tmpConstraint.setSymbol(constraints[j]["symbol"].GetString());
                tmpConstraint.setRange(constraints[j]["range"].GetString());
                pathSummary.addConstraints(tmpConstraint);
            }
        }
        if(program_state.HasMember("checker_messages") && !program_state["checker_messages"].IsNull()){
            rapidjson::Value &checkerMessages = program_state["checker_messages"];
            for (rapidjson::SizeType j = 0; j < checkerMessages.Size(); j++){
                JsonCheckerMessage tmpCheckerMessage;
                tmpCheckerMessage.setChecker(checkerMessages[j]["checker"].GetString());
                if(checkerMessages[j].HasMember("messages") && !checkerMessages[j]["messages"].Empty()){
                    rapidjson::Value &message = checkerMessages[j]["messages"];
                    for(rapidjson::SizeType k = 0; k < message.Size(); k++){
                        if(message[k].GetStringLength() > 0){
                            tmpCheckerMessage.addMessage(message[k].GetString());
                        }
                    }
                }
                pathSummary.addCheckerMessage(tmpCheckerMessage);
            }
        }
        if(program_state.HasMember("const_return_value") && !program_state["const_return_value"].IsNull()){
            rapidjson::Value &const_return_value = program_state["const_return_value"];
            pathSummary.setReturnValue(const_return_value.GetString(), ReturnValueType::CONSTANT);
        }else if(program_state.HasMember("environment") && !program_state["environment"].IsNull()){
            rapidjson::Value &environment = program_state["environment"];
            if(!environment.HasMember("items")){
                llvm::outs() << "wrong return value in environment, file: " << filePath << "\n";
            }else{
                rapidjson::Value &env_items = environment["items"];
                if(!env_items.IsNull() && !env_items.Empty()){
                    rapidjson::Value &items = env_items[0]["items"];
                    if(!items.IsNull() && !items.Empty()){
                        pathSummary.setReturnValue(items[0]["value"].GetString(), ReturnValueType::VARIABLE);
                        const std::string& tmp = pathSummary.getReturnValue();
                        if(tmp.find("local") != tmp.npos){
                            std::string localInfo = "";
                            std::size_t start = tmp.find("local");
                            std::size_t pos = start;
                            while(pos < tmp.size()){
                                if(tmp[pos] == ']'){
                                    break;
                                }
                                pos++;
                            }
                            if(pos == tmp.size()){
                                // ERROR!
                            }else{
                                localInfo = tmp.substr(start, pos - start);
                            }
                            pathSummary.dropDeadStores(localInfo);
                        }else{
                            pathSummary.dropDeadStores();
                        }
                    }
                }
            }
        }else{
            pathSummary.setReturnValue("", ReturnValueType::UNDIFINED);
        }
        summary.addPathSummary(pathSummary);
    }
    // add to out param
    outSummary = summary;
    return true;
}

void JsonSummaryManager::addSummary(const JsonSummary& summary){
    std::pair<decltype(this->summaryMap)::iterator, bool> retPair;
    retPair = summaryMap.insert({summary.getKey(),summary}); 
    if(retPair.second == false){
        llvm::errs() << "Summary already exists\n";
        summaryMap[summary.getKey()] = summary;
    }
}

bool JsonSummaryManager::searchSummaryFromDatabase(const JsonSummaryKey& key, JsonSummary& summary){
    // TODO search summary from database
    
    return false;
}

bool JsonSummaryManager::hasSummary(const JsonSummaryKey& key){
    // Backwards-compatible wrapper: extract name and call the new overload.
    const std::string full = key.getFunctionSignature();
    auto extractName = [](const std::string &s){
        size_t i = 0;
        while(i < s.size()){
            char c = s[i];
            if(std::isalnum((unsigned char)c) || c == '_' || c == ':' || c == '<' || c == '>' || c == '~'){
                ++i;
            } else break;
        }
        return s.substr(0,i);
    };
    std::string fname = extractName(full);
    if (fname.empty())
        return false;
    return hasSummary(key, fname);
}

bool JsonSummaryManager::hasSummary(const JsonSummaryKey& key, const std::string &calleeName){
    // If already parsed and cached, return quickly.
    if(this->summaryMap.find(key) != this->summaryMap.end()){
        return true;
    }

    // Try database if enabled
    if(this->databaseEnable){
        JsonSummary summary(key);
        if(searchSummaryFromDatabase(key,summary)){
            this->addSummary(summary);
            return true;
        }
    }

    if(calleeName.empty())
        return false;

    auto it = this->nameToFiles.find(calleeName);
    if(it == this->nameToFiles.end()){
        // no candidate files for this name -> no summary
        return false;
    }

    // Lazily parse candidate files for this function name.
    for(const std::string &filePath : it->second){
        JsonSummary parsed(JsonSummaryKey("NULL"));
        if(!parseSummaryFile(filePath, parsed))
            continue;
        this->addSummary(parsed);
        if(this->summaryMap.find(key) != this->summaryMap.end()){
            return true;
        }
    }

    return false;
}

JsonSummary JsonSummaryManager::getSummary(const JsonSummaryKey& key){

    if(this->hasSummary(key)){
        return this->summaryMap[key];
    }

    // Not found
    return JsonSummary(JsonSummaryKey("NULL"));
}
}
}



