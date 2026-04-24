//== JsonSummaryManager.h - Generic handling of json function summaries --*- C++ -*--==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defines JsonSummaryManager and related classes, which provides
//  a generic mechanism for managing json function summaries.
//
//===----------------------------------------------------------------------===//

#ifndef JSON_SUMMARY_MANAGER_H
#define JSON_SUMMARY_MANAGER_H

#include <string>
#include <unordered_map>
#include <vector>
// mongo include
// #include <bsoncxx/json.hpp>
// #include <mongocxx/client.hpp>
// #include <mongocxx/instance.hpp>
#include "clang/Basic/LLVM.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>

namespace clang {

namespace ento {

enum Language {
    C,
    CPP
};

enum ReturnValueType {
    CONSTANT,
    VARIABLE,
    UNDIFINED
};

class JsonStore{
public:
    JsonStore(const std::string& item_region, const std::string& value){
        this->item_region = item_region;
        this->value = value;
    }
    JsonStore(){

    }
    void setItem_Region(const std::string& item_region) {
        this->item_region = item_region;
    }
    void setValue(const std::string& value){
        this->value = value;
    }
    std::string getItem_Region() const {
        return this->item_region;
    }
    std::string getValue() const {
        return this->value;
    }
    void dumpToStream(llvm::raw_ostream &Out) const{
        Out << "\"item_region\": " << item_region << ", ";
        Out << "\"value\": " << value << "\n";
    }
    // llvm::raw_ostream& llvm::operator<<(llvm::raw_ostream &O, const JsonStore& jsonStore) {
    //     jsonStore.dumpToStream(O);
    //     return O;
    // }
private:
    std::string item_region;
    std::string value;
};

class JsonConstraint{
public:
    JsonConstraint(const std::string& symbol, const std::string& range){
        this->symbol = symbol;
        this->range = range;
    }
    JsonConstraint(){

    }
    void setSymbol(const std::string& symbol){
        this->symbol = symbol;
    }
    void setRange(const std::string& range){
        this->range = range;
    }
    std::string getSymbol() const {
        return this->symbol;
    }
    std::string getRange() const {
        return this->range;
    }
    void dumpToStream(llvm::raw_ostream &Out) const{
        Out << "\"symbol\": " << symbol << ", ";
        Out << "\"range\": " << range << "\n";
    }
    // llvm::raw_ostream& operator<<(llvm::raw_ostream &O, const JsonConstraint& jsonConstraints) {
    //     jsonConstraints.dumpToStream(O);
    //     return O;
    // }
private:
    std::string symbol;
    std::string range;
};

class JsonCheckerMessage{
public:
    JsonCheckerMessage(const std::string& checker, const std::vector<std::string>& messages){
        this->checker = checker;
        this->messages = messages;
    }
    JsonCheckerMessage(const std::string& checker){

    }
    JsonCheckerMessage(){

    }
    void setChecker(const std::string& checker){
        this->checker = checker;
    }
    void addMessage(const std::string& message){
        this->messages.push_back(message);
    }
    std::string getChecker() const {
        return this->checker;
    }
    std::vector<std::string> getMessages() const {
        return this->messages;
    }
    void dumpToStream(llvm::raw_ostream &Out) const{
        Out << "\"checker\": " << checker << ", ";
        Out << "\"messages\": [";
        for (int i = 0; i < (int)messages.size(); i++){
            Out << messages[i];
            if (i != (int)messages.size() - 1){
                Out << ", ";
            }
        }
        Out << "]\n";
    }
    // llvm::raw_ostream& operator<<(llvm::raw_ostream &O, const JsonCheckerMessage& jsonCheckerMessage) {
    //     jsonCheckerMessage.dumpToStream(O);
    //     return O;
    // }
private:
    std::string checker;
    std::vector<std::string> messages;
};

class JsonSummaryKey{
public:
    JsonSummaryKey(const std::string& functionSignature, const Language language=C){
        this->functionSignature = functionSignature;
        this->language = language;
    }
    JsonSummaryKey(){

    }
    std::string getFunctionSignature() const {
        return this->functionSignature;
    }
    Language getLanguage() const{
        return this->language;
    }
    bool operator==(const JsonSummaryKey& other) const {
        return this->functionSignature == other.functionSignature && this->language == other.language;
    }
    bool operator<(const JsonSummaryKey& other) const {
        return this->functionSignature < other.functionSignature || (this->functionSignature == other.functionSignature && this->language < other.language);
    }
    void dumpToStream(llvm::raw_ostream &Out) const{
        Out << "\"functionSignature\": " << functionSignature << "\n";
        // Out << "\"language\": " << language << "\n";
    }
    // llvm::raw_ostream& operator<<(llvm::raw_ostream &O, const JsonSummaryKey& jskey) {
    //     jskey.dumpToStream(O);
    //     return O;
    // }
    static size_t JsonSummaryKey_hash(const JsonSummaryKey& tmp)
    {
        return std::hash<std::string>()(tmp.functionSignature);
    }
private:
    std::string functionSignature;
    Language language;
};

class JsonPathSummary {
public:
    JsonPathSummary(){

    }
    void addStore(const JsonStore& store);
    void addConstraints(const JsonConstraint& constraint);
    void addCheckerMessage(const JsonCheckerMessage& checkerMessage);
    void setReturnValue(const std::string& returnValue, const ReturnValueType returnType = UNDIFINED);
    void dropDeadStores(const std::string& localInfo);
    void dropDeadStores();
    std::vector<JsonStore> getStores() const;
    std::vector<JsonConstraint> getConstraints() const;
    std::vector<JsonCheckerMessage> getCheckerMessages() const;
    std::string getReturnValue() const;
    ReturnValueType getReturnType() const;
    void dumpToStream(llvm::raw_ostream &Out) const{
        Out << "\"stores\": [";
        for (int i = 0; i < (int)stores.size(); i++){
            stores[i].dumpToStream(Out);
            if (i != (int)stores.size() - 1){
                Out << ", ";
            }
        }
        Out << "], \n";
        Out << "\"constraints\": [";
        for (int i = 0; i < (int)constraints.size(); i++){
            constraints[i].dumpToStream(Out);
            if (i != (int)constraints.size() - 1){
                Out << ", ";
            }
        }
        Out << "], \n";
        Out << "\"checkerMessages\": [";
        for (int i = 0; i < (int)checkerMessages.size(); i++){
            checkerMessages[i].dumpToStream(Out);
            if (i != (int)checkerMessages.size() - 1){
                Out << ", ";
            }
        }
        Out << "], \n";
        Out << "\"returnValue\": " << returnValue << "\n";
    }
    // llvm::raw_ostream& operator<<(llvm::raw_ostream &O, const JsonSummary& jsonSummary) {
    //     jsonSummary.dumpToStream(O);
    //     return O;
    // }

private:
    std::vector<JsonStore> stores;
    std::vector<JsonConstraint> constraints;
    std::vector<JsonCheckerMessage> checkerMessages;
    std::string returnValue;
    ReturnValueType returnType;
};

class JsonSummary {
public:
    JsonSummary(){

    }
    JsonSummary(const JsonSummaryKey& key){
        this->summaryKey = key;
    }
    void setSummaryKey(const JsonSummaryKey& summaryKey);
    void addPathSummary(const JsonPathSummary& pathSummary);
    JsonSummaryKey getKey() const;
    std::vector<JsonPathSummary> getPathSummaries() const;
    void dumpToStream(llvm::raw_ostream &Out) const{
        Out << "\"summaryKey\": ";
        summaryKey.dumpToStream(Out);
        Out << ", ";
        Out << "\"pathSummaries\": [";
        for (int i = 0; i < (int)pathSummaries.size(); i++){
            pathSummaries[i].dumpToStream(Out);
            if (i != (int)pathSummaries.size() - 1){
                Out << ", ";
            }
        }
        Out << "]\n";
    }
private:
    JsonSummaryKey summaryKey;
    std::vector<JsonPathSummary> pathSummaries;
};

struct hashFunctionSignature
{
    size_t operator()(const JsonSummaryKey& tmp) const
    {
        return (std::hash<std::string>()(tmp.getFunctionSignature()));
    }
};

class JsonSummaryManager {
public:
    JsonSummaryManager(){}
    void loadSummaries(std::string);
    void addSummary(const JsonSummary&);
    // Primary API: check whether a summary with the given key exists.
    // If the caller already has the callee name (cheap), use the overload
    // that accepts it to avoid re-parsing the key.
    bool hasSummary(const JsonSummaryKey&);
    bool hasSummary(const JsonSummaryKey& key, const std::string &calleeName);
    JsonSummary getSummary(const JsonSummaryKey&);

private:
    std::unordered_map<JsonSummaryKey, JsonSummary, hashFunctionSignature> summaryMap;
    bool databaseEnable = false;
    bool searchSummaryFromDatabase(const JsonSummaryKey&, JsonSummary&);
    void getFileLists(const std::string&, std::vector<std::string> &lists);
    // Lazy-loading support: map from function name -> candidate summary file(s)
    std::unordered_map<std::string, std::vector<std::string>> nameToFiles;
    // Parse a single file into a JsonSummary. Returns true on success.
    bool parseSummaryFile(const std::string &filePath, JsonSummary &outSummary);
    // TODO mongo file
    // mongocxx::instance inst{};
};
}
}

#endif // JSON_SUMMARY_MANAGER_H