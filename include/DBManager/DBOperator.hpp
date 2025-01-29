#pragma once

#include <odb/database.hxx>
#include <odb/connection.hxx>
#include <odb/transaction.hxx>
#include <odb/schema-catalog.hxx>
#include <odb/tracer.hxx>

#include <odb/sqlite/database.hxx>
#include <odb/sqlite/exceptions.hxx>

#include <cstring>
#include <mutex>
#include <memory>
#include <vector>
#include <list>
#include <map>

#include "IntellBoxCommon/SDKInterfaces/Error.h"
#include "IntellBoxCommon/Utils/Logger/Logger.h"

namespace intellBoxSDK {

class DBTracer : public odb::tracer {
public:
    virtual void prepare(odb::connection&, const odb::statement&);
    virtual void execute(odb::connection&, const odb::statement&);
    virtual void execute(odb::connection&, const char* statement);
    virtual void deallocate(odb::connection&, const odb::statement&);

private:
    friend odb::database;
    friend odb::transaction;
    friend odb::connection;
};

class DBOperator {
public:
    template <class T>
    using odbQuery = odb::query<T>;
    template <class T>
    using odbResult = odb::result<T>;

    ~DBOperator();
    static std::shared_ptr<DBOperator> create(const std::string& dbName, bool trace = false);

    Error createTable(const std::string& schemaName, bool force = false);
    Error dropTable(const std::string& schemaName);

    template <class T>
    Error insert(const T);
    template <class T>
    Error insert(const std::vector<T>);
    template <class T>
    friend Error insertExt(std::shared_ptr<DBOperator> manager, const T);
    template <class T>
    friend Error insertSetsExt(std::shared_ptr<DBOperator> manager, const std::vector<T>);
    template <class T>
    Error update(const T);
    template <class T>
    Error update(const std::vector<T>);
    template <class T>
    Error remove(const T);
    template <class T>
    Error remove(const std::vector<T>);

    template <class T>
    Error load(const typename odb::object_traits<T>::id_type&, T&);
    template <class T>
    Error reload(T&);

    template <class T>
    void addQueryCond(std::list<odbQuery<T>>& list, const odbQuery<T> cond);
    template <class T, class Cond>
    void delQueryCond(std::list<odbQuery<T>>& list, Cond cond);
    template <class T>
    odbQuery<T> queryConditionsOr(std::list<odbQuery<T>>& queryCondition);
    template <class T>
    odbQuery<T> queryConditionsAnd(std::list<odbQuery<T>>& queryCondition);

    template <class T, class Args>
    friend Error checkView(std::shared_ptr<DBOperator> manager, odbQuery<T> cond, Args& args);
    template <class T, class... Args>
    friend Error search(std::shared_ptr<DBOperator> manager, odbQuery<T> cond, std::list<T>& results, Args... args);
    template <class T>
    Error search(odbQuery<T> cond, std::list<T>& results, int size = 0, int offset = 0);
    template <class... Args>
    Error search(Args... args);

    Error execSQL(const std::string);

private:
    DBOperator(bool trace);
    Error initialize(const std::string& dbName);

    std::shared_ptr<odb::database> m_db;
    std::mutex m_mutex;
    bool m_trace;
    DBTracer m_debug;
};

}  // namespace intellBoxSDK

namespace intellBoxSDK {

using namespace odb::core;

#define EXEC_START(obj)                                                     \
    if (odb::transaction::has_current()) odb::transaction::reset_current(); \
    std::unique_lock<std::mutex> lock(obj->m_mutex);                        \
    odb::transaction tr(obj->m_db->begin());                                \
    if (obj->m_trace) {                                                     \
        tr.tracer(obj->m_debug);                                            \
    }                                                                       \
    try {
#define EXEC_END                                                                                                \
    tr.commit();                                                                                                \
    }                                                                                                           \
    catch (const odb::object_already_persistent& e) {                                                           \
        LOG_ERROR("[{0}][{1}] {2}", __FUNCTION__, __LINE__, e.what());                                          \
        return Error::NAME_EXIST;                                                                               \
    }                                                                                                           \
    catch (const odb::object_not_persistent& e) {                                                               \
        LOG_ERROR("[{0}][{1}] {2}", __FUNCTION__, __LINE__, e.what());                                          \
        return Error::NO_SUCH_RECORD;                                                                           \
    }                                                                                                           \
    catch (const odb::unknown_schema& e) {                                                                      \
        LOG_ERROR("[{0}][{1}] {2}", __FUNCTION__, __LINE__, e.what());                                          \
        return Error::NO_SUCH_RECORD;                                                                           \
    }                                                                                                           \
    catch (const odb::sqlite::database_exception& e) {                                                          \
        LOG_ERROR("[{0}][{1}] Database error: {2}, errcode: {3}", __FUNCTION__, __LINE__, e.what(), e.error()); \
        if (1 == e.error()) {                                                                                   \
            return Error::NAME_EXIST;                                                                           \
        }                                                                                                       \
        return Error::NO_SUCH_RECORD;                                                                           \
    }                                                                                                           \
    catch (const odb::exception& e) {                                                                           \
        LOG_ERROR("[{0}][{1}] Exception: {2}, Type: {3}", __FUNCTION__, __LINE__, e.what(), typeid(e).name());  \
        return Error::GENERAL_FAIL;                                                                             \
    }                                                                                                           \
    return Error::SUCCESS;

#define execFunc(func, ...) \
    EXEC_START(this) {      \
        func(__VA_ARGS__);  \
    }                       \
    EXEC_END

#define execSets(func, data)    \
    EXEC_START(this) {          \
        for (auto val : data) { \
            func(val);          \
        }                       \
    }                           \
    EXEC_END

#define condRecursion(func, cond, opt)     \
    if (cond.empty()) {                    \
        return odbQuery<T>();              \
    }                                      \
                                           \
    odbQuery<T> qCondition = cond.front(); \
    cond.pop_front();                      \
    if (cond.size() == 0) {                \
        return qCondition;                 \
    }                                      \
    return func(cond) opt qCondition;

DBOperator::DBOperator(bool trace) : m_trace(trace) {
}
DBOperator::~DBOperator() {
}

std::shared_ptr<DBOperator> DBOperator::create(const std::string& dbName, bool trace) {
    auto dbManager = std::shared_ptr<DBOperator>(new DBOperator(trace));
    if (dbManager) {
        if (Error::SUCCESS == dbManager->initialize(dbName)) {
            return dbManager;
        }
    }
    return nullptr;
}

Error DBOperator::initialize(const std::string& dbName) {
    try {
        m_db = std::shared_ptr<odb::database>(new odb::sqlite::database(dbName.c_str(), SQLITE_OPEN_READWRITE));
        odb::connection_ptr connectionPtr(m_db->connection());
        odb::transaction tr(connectionPtr->begin());
        tr.commit();
    } catch (const odb::exception& e) {
        try {
            m_db = std::shared_ptr<odb::database>(
                new odb::sqlite::database(dbName.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE));
            odb::connection_ptr connectionPtr(m_db->connection());
            odb::transaction tr(connectionPtr->begin());
            tr.commit();
        } catch (const odb::exception& e) {
            LOG_ERROR("[{0}][{1}] Create db failed. name: {2}", __FUNCTION__, __LINE__, dbName);
            return Error::NO_ENOUGH_SPACE;
        }
    }
    return Error::SUCCESS;
}

Error DBOperator::createTable(const std::string& schemaName, bool force){
    EXEC_START(this){auto retVal = odb::schema_catalog::exists(m_db->id(), schemaName);
if (!retVal) {
    LOG_ERROR("[{0}][{1}] Not found {2}, please premap.", __FUNCTION__, __LINE__, schemaName);
}

odb::schema_catalog::create_schema(*m_db, schemaName, force);
}  // namespace intellBoxSDK
EXEC_END
}

Error DBOperator::dropTable(const std::string& schemaName) {
    execFunc(odb::schema_catalog::drop_schema, *m_db, schemaName);
}

template <class T>
Error DBOperator::insert(const T val) {
    execFunc(m_db->persist, val)
}

template <class T>
Error DBOperator::insert(const std::vector<T> data) {
    execSets(m_db->persist, data)
}

template <class T>
Error DBOperator::update(const T val) {
    execFunc(m_db->update, val)
}

template <class T>
Error DBOperator::update(const std::vector<T> data) {
    execSets(m_db->update, data)
}

template <class T>
Error DBOperator::remove(const T val) {
    execFunc(m_db->erase, val)
}

template <class T>
Error DBOperator::remove(const std::vector<T> data) {
    execSets(m_db->erase, data)
}

template <class T>
Error DBOperator::load(const typename odb::object_traits<T>::id_type& id, T& obj) {
    execFunc(m_db->load, id, obj);
}

template <class T>
Error DBOperator::reload(T& obj) {
    execFunc(m_db->reload, obj);
}

template <class T>
void DBOperator::addQueryCond(std::list<odbQuery<T>>& list, const odbQuery<T> cond) {
    list.push_back(cond);
}

template <class T, class Cond>
void DBOperator::delQueryCond(std::list<odbQuery<T>>& list, Cond cond) {
    list.erase(cond);
}

template <class T>
DBOperator::odbQuery<T> DBOperator::queryConditionsOr(std::list<odbQuery<T>>& queryCondition) {
    condRecursion(queryConditionsOr, queryCondition, ||);
}

template <class T>
DBOperator::odbQuery<T> DBOperator::queryConditionsAnd(std::list<odbQuery<T>>& queryCondition) {
    condRecursion(queryConditionsAnd, queryCondition, &&);
}

template <class T>
Error DBOperator::search(odbQuery<T> cond, std::list<T>& results, int size, int offset) {
    std::string queryCond;
    if (size > 0) {
        queryCond += " limit " + std::to_string(size);
        if (offset > 0) {
            queryCond += " offset " + std::to_string(offset);
        }
    }

    EXEC_START(this) {
        odbResult<T> result;
        result = odbResult<T>(m_db->query<T>(cond + queryCond));
        results.insert(results.begin(), result.begin(), result.end());
    }
    EXEC_END
}

Error DBOperator::execSQL(const std::string sql) {
    execFunc(m_db->execute, sql)
}

void DBTracer::prepare(odb::connection& c, const odb::statement& s) {
    LOG_INFO("[{0}][{1}] {2}", __FUNCTION__, __LINE__, s.text());
}

void DBTracer::execute(odb::connection& c, const odb::statement& s) {
    LOG_INFO("[{0}][{1}] {2}", __FUNCTION__, __LINE__, s.text());
}

void DBTracer::execute(odb::connection& c, const char* statement) {
    LOG_INFO("[{0}][{1}] {2}", __FUNCTION__, __LINE__, statement);
}

void DBTracer::deallocate(odb::connection& c, const odb::statement& s) {
    LOG_INFO("[{0}][{1}] {2}", __FUNCTION__, __LINE__, s.text());
}

}  // namespace intellBoxSDK
