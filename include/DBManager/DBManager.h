#pragma once

#include <memory>
#include <thread>
#include <mutex>
#include <map>
#include <set>
#include <typeinfo>
#include <typeindex>
#include <cstring>
#include <unordered_map>

#include "Error.h"
#include "CppSQLite3/CppSQLite3.h"

namespace my_toolskit {

class DBManager {
public:
    ~DBManager();
    static std::shared_ptr<DBManager> create(const std::string dbFile);
    Error create(
        const std::string& tableName,
        const std::map<std::string, std::string> items,
        const std::string& key = {});
    Error insert(const std::string& tableName, const std::map<std::string, std::string> items);
    void select(
        const std::string& tableName,
        std::set<std::map<std::string, std::string>>& results,
        const std::map<std::string, std::string>& item = {},
        const std::string& selectItem = {});
    Error update(
        const std::string& tableName,
        const std::map<std::string, std::string> items,
        const std::map<std::string, std::string>& condition);
    Error del(const std::string& tableName, const std::map<std::string, std::string>& item = {});
    Error drop(const std::string& tableName);
    std::string convertType(const std::type_info& typeInfo);

private:
    DBManager();
    Error initialize(const std::string dbFile);
    std::shared_ptr<CppSQLite3DB> m_sqliteDB;
    std::mutex m_sqliteMutex;
    std::unordered_map<std::type_index, std::string> m_typeNames;
};

}  // namespace my_toolskit
