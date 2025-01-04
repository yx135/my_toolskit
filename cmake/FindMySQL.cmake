# - Find MySQL/MariaDB
# Find the MySQL/MariaDB includes and client library
# This module defines
#  MYSQL_INCLUDE_DIR, where to find mysql.h
#  MYSQL_LIBRARY, the libraries needed to use MySQL.
#  MYSQL_FOUND, If false, do not try to use MySQL.

find_path(MYSQL_INCLUDE_DIR mysql.h
    /usr/include/mariadb
    /usr/include/mysql
    /usr/local/include/mysql
    /opt/mysql/mysql/include
    /opt/mysql/mysql/include/mysql
    /usr/local/mysql/include
    /usr/local/mysql/include/mysql
    $ENV{MYSQL_INCLUDE_DIR}
)

find_library(MYSQL_LIBRARY NAMES mariadb mysqlclient
    PATHS
    /usr/lib/x86_64-linux-gnu
    /usr/lib
    /usr/lib/mysql
    /usr/local/lib
    /usr/local/lib/mysql
    /opt/mysql/mysql/lib
    /opt/mysql/mysql/lib/mysql
    /usr/local/mysql/lib
    $ENV{MYSQL_LIB_DIR}
)

if(MYSQL_INCLUDE_DIR AND MYSQL_LIBRARY)
    set(MYSQL_FOUND TRUE)
    message(STATUS "Found MySQL/MariaDB: ${MYSQL_INCLUDE_DIR}, ${MYSQL_LIBRARY}")
else()
    set(MYSQL_FOUND FALSE)
    message(STATUS "MySQL/MariaDB not found.")
endif()

mark_as_advanced(
    MYSQL_INCLUDE_DIR
    MYSQL_LIBRARY
) 