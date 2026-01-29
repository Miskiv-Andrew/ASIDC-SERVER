cmake_minimum_required(VERSION 3.16)

project(GuarderServerCLI LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =========================
# Dependencies
# =========================
include(FetchContent)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(JSONCPP_WITH_TESTS OFF CACHE BOOL "" FORCE)
set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    jsoncpp
    GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp.git
    GIT_TAG        1.9.5
)

FetchContent_MakeAvailable(jsoncpp)

# =========================
# Sources
# =========================
add_executable(${PROJECT_NAME}
    apps/main_cli.cpp

    core/servercore.cpp
    core/databasemanager.cpp
    core/passwordhasher.cpp

    third_party/nanodbc/nanodbc.cpp
    third_party/civetweb/civetweb.c
)

# =========================
# Include dirs
# =========================
target_include_directories(${PROJECT_NAME} PRIVATE
    core
    third_party/nanodbc
    third_party/civetweb
)

# =========================
# CivetWeb
# =========================
target_compile_definitions(${PROJECT_NAME} PRIVATE
    USE_SSL
    NO_CGI
    NO_FILES
)

# =========================
# Link libraries (COMMON)
# =========================
target_link_libraries(${PROJECT_NAME} PRIVATE
    jsoncpp_static
)

# =========================
# Platform specific
# =========================
if(UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        odbc
        ssl
        crypto
        pthread
        dl
    )
endif()

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE odbc32)

    if(DEFINED ENV{OPENSSL_PATH})
        target_include_directories(${PROJECT_NAME} PRIVATE
            $ENV{OPENSSL_PATH}/include
        )
        target_link_directories(${PROJECT_NAME} PRIVATE
            $ENV{OPENSSL_PATH}/lib/VC/x64/MD
        )
        target_link_libraries(${PROJECT_NAME} PRIVATE
            libssl
            libcrypto
        )
    endif()
endif()

# =========================
# Certificates
# =========================
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/config
        "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
    COMMENT "Copying config directory"
)

# =========================
# SQL Script copy
# =========================
# Путь к SQL скрипту
set(SQL_INIT_FILE "${CMAKE_SOURCE_DIR}/db/init/001_init.sql")

# Проверяем существование файла
if(EXISTS "${SQL_INIT_FILE}")
    message(STATUS "SQL init file found: ${SQL_INIT_FILE}")

    # Создаем структуру папок db/init/ рядом с exe
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/db/init"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SQL_INIT_FILE}"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/db/init/001_init.sql"
        COMMENT "Copying SQL initialization script to db/init/"
    )

    # Также копируем в корень рядом с exe (для удобства)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SQL_INIT_FILE}"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/001_init.sql"
        COMMENT "Copying SQL script to exe directory"
    )
else()
    message(WARNING "SQL init file NOT found: ${SQL_INIT_FILE}")
endif()
