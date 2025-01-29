
#include "IntellBoxCommon/Utils/OdbSqlite3/OdbSqlite3.h"

namespace intellBoxSDK {

std::shared_ptr<odb::sqlite::database> OdbSqlite3::open_database(
    const std::string& name,
    const std::string& schemaName,
    bool create) {
    int flags = SQLITE_OPEN_READWRITE;
    if (create) flags |= SQLITE_OPEN_CREATE;

    std::shared_ptr<odb::sqlite::database> db(new odb::sqlite::database(name, flags));
    odb::transaction t(db->begin());
    if (create) {
        odb::schema_catalog::create_schema(*db, schemaName, false);
    }
    t.commit();

    return db;
}

std::shared_ptr<odb::sqlite::database> OdbSqlite3::open_create_database(
    const std::string& name,
    const std::string& schemaName) {
    std::shared_ptr<odb::sqlite::database> db;
    try {
        db = open_database(name, schemaName, false);
    } catch (const odb::exception& e) {
        try {
            db = open_database(name, schemaName, true);
        } catch (const odb::exception& e) {
        }
    }
    return db;
}

}  // namespace intellBoxSDK
