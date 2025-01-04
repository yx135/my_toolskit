# My ToolsKit

这是一个 C++ 工具库项目，提供了数据库操作等常用功能的封装。

## 功能特性

- MySQL/MariaDB 数据库操作封装
- 更多功能开发中...

## 依赖要求

- CMake (>= 3.10)
- C++ 编译器 (支持 C++14)
- MariaDB/MySQL 开发库

### 在 Debian/Ubuntu 上安装依赖

```bash
sudo apt-get update
sudo apt-get install build-essential cmake libmariadb-dev
```

### 在 CentOS/RHEL 上安装依赖

```bash
sudo yum install gcc gcc-c++ cmake mariadb-devel
```

## 编译步骤

1. 创建并进入构建目录：

```bash
mkdir build
cd build
```

2. 配置项目：

```bash
cmake ..
```

默认情况下会编译成动态库。编译完成后，动态库文件会在 `build/lib` 目录下。

3. 编译项目：

```bash
make
```

4. （可选）安装到系统：

```bash
sudo make install
```

安装后，动态库将被安装到系统的库目录（通常是 `/usr/local/lib`），头文件会被安装到 `/usr/local/include`。

### 使用已安装的库

安装后，你需要更新系统的动态库缓存：

```bash
sudo ldconfig
```

## 使用示例

```cpp
#include <my_toolskit/db/mysql/MysqlCapi.h>

int main() {
    Connection conn;
    if (conn.connect("localhost", 3306, "username", "password", "dbname")) {
        // 执行查询
        MYSQL_RES* res = conn.query("SELECT * FROM users");
        // 处理结果...
        
        // 执行更新
        bool success = conn.update("INSERT INTO users (name) VALUES ('test')");
    }
    return 0;
}
```

### 链接动态库

在你的项目的 CMakeLists.txt 中：

```cmake
find_package(my_toolskit REQUIRED)
target_link_libraries(your_target my_toolskit)
```

或者使用 g++ 编译：

```bash
g++ your_program.cpp -lmy_toolskit
```

## 项目结构

```
my_toolskit/
├── include/             # 头文件目录
│   └── db/
│       └── mysql/      # MySQL 相关头文件
├── src/                # 源文件目录
│   └── db/
│       └── mysql/      # MySQL 相关实现
├── cmake/              # CMake 模块
├── examples/           # 示例代码
├── tests/              # 测试代码
└── CMakeLists.txt     # CMake 构建配置
```

## 许可证

[待添加许可证信息]

## 贡献指南

1. Fork 本项目
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开一个 Pull Request
