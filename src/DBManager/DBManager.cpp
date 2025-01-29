#include "DBManager/DBManager.h"
#include "Logger/Logger.h"

namespace my_toolskit {

#define WS " "
#define LB "("
#define RB ")"
#define LSB "["
#define RSB "]"
#define COMMA ","
#define AR "*"
#define QM "?"
#define EQ "="
#define SQ "'"
#define AND "and"
#define SEMICOLON ";"
#define ENABLE_FLAG -1
#define DISABLE_FLAG 0

const std::string db_item[] = {"NULL", "INTEGER", "REAL", "TEXT", "BLOB"};
const std::string db_cmd[] = {"CREATE", "INSERT", "SELECT", "UPDATE", "DELETE", "DROP"};

enum class DB_CMD { DB_CREATE, DB_INSERT, DB_SELECT, DB_UPDATE, DB_DELETE, DB_DROP };

enum class DB_ITEM_TYPE { DB_NULL, DB_INTEGER, DB_REAL, DB_TEXT, DB_BLOB };

DBManager::DBManager() {
    m_typeNames[std::type_index(typeid(int))] = "int";
    m_typeNames[std::type_index(typeid(std::string))] = "string";
}
DBManager::~DBManager() {
    m_sqliteDB->close();
}

std::string DBManager::convertType(const std::type_info& typeInfo) {
    if (!strcmp(m_typeNames[std::type_index(typeInfo)].c_str(), "int")) {
        return db_item[static_cast<int>(DB_ITEM_TYPE::DB_INTEGER)];
    } else if (!strcmp(m_typeNames[std::type_index(typeInfo)].c_str(), "string")) {
        return db_item[static_cast<int>(DB_ITEM_TYPE::DB_TEXT)];
    }

    return db_item[static_cast<int>(DB_ITEM_TYPE::DB_INTEGER)];
}

std::shared_ptr<DBManager> DBManager::create(const std::string dbFile) {
    auto db = std::shared_ptr<DBManager>(new DBManager());
    if (db) {
        if (Error::SUCCESS == db->initialize(dbFile)) {
            return db;
        }
    }
    return nullptr;
}

Error DBManager::initialize(const std::string dbFile) {
    m_sqliteDB = std::unique_ptr<CppSQLite3DB>(new CppSQLite3DB());
    if (nullptr == m_sqliteDB) {
        LOG_ERROR("Create DB failed.");
        return Error::INITIAL_FAIL;
    }

    try {
        m_sqliteDB->open(dbFile.c_str());
    } catch (CppSQLite3Exception& sqliteException) {
        LOG_ERROR("Open DB faile failed.");
        return Error::DB_FAIL;
    }

    return Error::SUCCESS;
}

Error DBManager::create(
    const std::string& tableName,
    const std::map<std::string, std::string> items,
    const std::string& key) {
    std::string cmd;
    cmd += db_cmd[static_cast<int>(DB_CMD::DB_CREATE)];
    cmd += WS;
    cmd += "TABLE IF NOT EXISTS";
    cmd += WS;
    cmd += tableName;
    cmd += LB;
    for (auto item : items) {
        cmd += LSB;
        cmd += item.first;
        cmd += RSB;
        cmd += WS;

        cmd += item.second;
        if (key == item.first) {
            cmd += WS;
            cmd += "PRIMARY KEY";
        }
        cmd += COMMA;
    }

    cmd.erase(cmd.end() - 1);
    cmd += RB;
    cmd += SEMICOLON;

    try {
        m_sqliteDB->execDML(cmd.c_str());
    } catch (CppSQLite3Exception& sqliteException) {
        LOG_ERROR("Create table {0} failed.", tableName);
        return Error::DB_FAIL;
    }

    return Error::SUCCESS;
}

Error DBManager::insert(const std::string& tableName, const std::map<std::string, std::string> items) {
    std::string cmd;
    cmd += db_cmd[static_cast<int>(DB_CMD::DB_INSERT)];
    cmd += WS;
    cmd += "INTO";
    cmd += WS;
    cmd += tableName;
    cmd += LB;
    for (auto item : items) {
        cmd += item.first;
        cmd += COMMA;
    }

    cmd.erase(cmd.end() - 1);
    cmd += RB;
    cmd += WS;
    cmd += "VALUES";
    cmd += LB;
    for (size_t i = items.size(); i > 0; i--) {
        cmd += QM;
        cmd += COMMA;
    }

    cmd.erase(cmd.end() - 1);
    cmd += RB;

    std::unique_lock<std::mutex> lock(m_sqliteMutex);
    CppSQLite3Statement stmt = m_sqliteDB->compileStatement(cmd.c_str());
    int i = 1;
    for (auto item : items) {
        stmt.bind(i, item.second.c_str());
        ++i;
    }

    try {
        stmt.execDML();
    } catch (CppSQLite3Exception& sqliteException) {
        LOG_ERROR("Insert failed. ErrorMsg: {0}", sqliteException.errorMessage());
        ;
        return Error::DB_FAIL;
    }
    return Error::SUCCESS;
}

void DBManager::select(
    const std::string& tableName,
    std::set<std::map<std::string, std::string>>& results,
    const std::map<std::string, std::string>& item,
    const std::string& selectItem) {
    std::string cmd;
    cmd += db_cmd[static_cast<int>(DB_CMD::DB_SELECT)];
    cmd += WS;
    if (selectItem.empty()) {
        cmd += AR;
    } else {
        cmd += selectItem;
    }
    cmd += WS;
    cmd += "FROM";
    cmd += WS;
    cmd += tableName;

    if (item.size()) {
        cmd += WS;
        cmd += "WHERE";
        cmd += WS;

        for (auto it : item) {
            cmd += it.first;
            cmd += EQ;
            cmd += QM;
        }
    }

    std::unique_lock<std::mutex> lock(m_sqliteMutex);
    auto stmt = m_sqliteDB->compileStatement(cmd.c_str());

    if (item.size()) {
        int i = 1;
        for (auto it : item) {
            stmt.bind(i, it.second.c_str());
            ++i;
        };
    }

    auto result = stmt.execQuery();
    while (!result.eof()) {
        int size = result.numFields();
        std::map<std::string, std::string> dbInfos;
        // results.insert(std::make_pair(result.numFields());
        for (int i = 0; i < size; i++) {
            dbInfos.insert(std::make_pair(result.fieldName(i), result.getStringField(i)));
        }
        results.insert(dbInfos);
        result.nextRow();
    }
}

Error DBManager::update(
    const std::string& tableName,
    const std::map<std::string, std::string> items,
    const std::map<std::string, std::string>& condition) {
    std::string cmd;
    cmd += db_cmd[static_cast<int>(DB_CMD::DB_UPDATE)];
    cmd += WS;
    cmd += tableName;
    cmd += WS;

    cmd += "SET";
    cmd += WS;

    for (auto item : items) {
        cmd += item.first;
        cmd += EQ;
        cmd += QM;
        cmd += COMMA;
    }

    cmd.erase(cmd.end() - 1);

    if (condition.size() > 0) {
        cmd += WS;
        cmd += "WHERE";
    }

    for (auto item : condition) {
        cmd += WS;
        cmd += item.first;
        cmd += EQ;
        cmd += SQ;
        cmd += item.second;
        cmd += SQ;
        cmd += AND;
    }

    if (condition.size() > 0) {
        for (int i = 0; i < 3; i++) cmd.erase(cmd.end() - 1);
    }

    std::unique_lock<std::mutex> lock(m_sqliteMutex);
    CppSQLite3Statement stmt = m_sqliteDB->compileStatement(cmd.c_str());
    int i = 1;
    for (auto item : items) {
        stmt.bind(i, item.second.c_str());
        ++i;
    }

    try {
        stmt.execDML();
    } catch (CppSQLite3Exception& sqliteException) {
        LOG_ERROR("Update failed. ErrorMsg: {0}", sqliteException.errorMessage());
        return Error::DB_FAIL;
    }

    return Error::SUCCESS;
}

Error DBManager::del(const std::string& tableName, const std::map<std::string, std::string>& item) {
    std::string cmd;
    cmd += db_cmd[static_cast<int>(DB_CMD::DB_DELETE)];
    cmd += WS;
    cmd += "FROM";
    cmd += WS;
    cmd += tableName;

    if (item.size()) {
        cmd += WS;
        cmd += "WHERE";
        cmd += WS;

        for (auto it : item) {
            cmd += it.first;
            cmd += EQ;
            cmd += SQ;
            cmd += it.second;
            cmd += SQ;
            cmd += COMMA;
        }
        cmd.erase(cmd.end() - 1);
    }

    try {
        m_sqliteDB->execDML(cmd.c_str());
    } catch (CppSQLite3Exception& sqliteException) {
        for (auto it : item) {
            LOG_ERROR("Delete {0} {1} failed.", it.first, it.second);
        }
        return Error::DB_FAIL;
    }

    return Error::SUCCESS;
}

Error DBManager::drop(const std::string& tableName) {
    std::string cmd;
    cmd += db_cmd[static_cast<int>(DB_CMD::DB_DROP)];
    cmd += WS;
    cmd += "TABLE";
    cmd += WS;
    cmd += tableName;

    try {
        m_sqliteDB->execDML(cmd.c_str());
    } catch (CppSQLite3Exception& sqliteException) {
        LOG_ERROR("Drop table {0} failed.", tableName);
        return Error::DB_FAIL;
    }

    return Error::SUCCESS;
}

}  // namespace my_toolskit
