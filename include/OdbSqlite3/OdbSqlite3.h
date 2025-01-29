#pragma once

#include <memory>
#include <string>
#include <odb/database.hxx>
#include <odb/transaction.hxx>
#include <odb/schema-catalog.hxx>
#include <odb/sqlite/database.hxx>

namespace intellBoxSDK {
class OdbSqlite3 {
public:
    static std::shared_ptr<odb::sqlite::database> open_database(const std::string& name, const std::string& schemaName, bool create);
    static std::shared_ptr<odb::sqlite::database> open_create_database(const std::string& name, const std::string& schemaName);
};

}  // namespace intellBoxSDK
