cmake_minimum_required(VERSION 3.16)

project(GuarderServerCLI LANGUAGES C CXX)

# =========================
# Global settings
# =========================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(BUILD_SHARED_LIBS OFF)

# Отключаем санитайзеры в зависимости от компилятора
if(MSVC)
    # Для MSVC/clang-cl
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} /fsanitize=address-")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /fsanitize=address-")
    set(CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG} /fsanitize=address-")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address-")
else()
    # Для GCC/Clang на Linux
    string(REPLACE "-fsanitize=address" "" CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}")
    string(REPLACE "-fsanitize=address" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REPLACE "-fsanitize=address" "" CMAKE_C_FLAGS_DEBUG   "${CMAKE_C_FLAGS_DEBUG}")
    string(REPLACE "-fsanitize=address" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
endif()

# =========================
# FetchContent
# =========================
include(FetchContent)

# =========================
# CivetWeb configuration
# =========================
set(CIVETWEB_ENABLE_SSL ON CACHE BOOL "Enable SSL support" FORCE)

set(CIVETWEB_SSL_OPENSSL_API_1_0 OFF CACHE BOOL "" FORCE)
set(CIVETWEB_SSL_OPENSSL_API_1_1 OFF CACHE BOOL "" FORCE)
set(CIVETWEB_SSL_OPENSSL_API_3_0 ON  CACHE BOOL "" FORCE)

set(CIVETWEB_ENABLE_CGI OFF CACHE BOOL "" FORCE)
set(CIVETWEB_ENABLE_FILES OFF CACHE BOOL "" FORCE)
set(CIVETWEB_BUILD_TESTING OFF CACHE BOOL "" FORCE)

# Disable ASAN for CivetWeb
set(CIVETWEB_ENABLE_ASAN OFF CACHE BOOL "" FORCE)

# ВАЖНО: Отключаем динамическую загрузку SSL - линкуем статически
set(CIVETWEB_ENABLE_SSL_DYNAMIC_LOADING OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    civetweb
    GIT_REPOSITORY https://github.com/civetweb/civetweb.git
    GIT_TAG        master
)

# =========================
# JsonCpp
# =========================
set(JSONCPP_WITH_TESTS OFF CACHE BOOL "" FORCE)
set(JSONCPP_WITH_POST_BUILD_UNITTEST OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(BUILD_OBJECT_LIBS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    jsoncpp
    GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp.git
    GIT_TAG        1.9.5
)

# =========================
# Make dependencies available
# =========================
FetchContent_MakeAvailable(civetweb jsoncpp)


# =========================
# Executable
# =========================
add_executable(${PROJECT_NAME}
    apps/main_cli.cpp

    core/servercore.cpp
    core/databasemanager.cpp
    core/passwordhasher.cpp

    third_party/nanodbc/nanodbc.cpp
)

# =========================
# Include directories
# =========================
target_include_directories(${PROJECT_NAME} PRIVATE
    core
    third_party/nanodbc
    third_party/civetweb
)

# =========================
# Link libraries
# =========================
target_link_libraries(${PROJECT_NAME} PRIVATE
    jsoncpp_static
)

# =========================
# Platform specific
# =========================
if(UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE
		civetweb-c-library PUBLIC ssl crypto
        ssl
        crypto
        odbc
        pthread
        dl
    )
endif()

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE
		civetweb-c-library
        odbc32
        libcrypto
        libssl
    )

    if(DEFINED ENV{OPENSSL_PATH})
        target_include_directories(${PROJECT_NAME} PRIVATE
            $ENV{OPENSSL_PATH}/include
        )
        target_link_directories(${PROJECT_NAME} PRIVATE
            $ENV{OPENSSL_PATH}/lib/VC/x64/MD
        )
    endif()
endif()

# =========================
# Certificates (optional - only if config exists)
# =========================
if(EXISTS "${CMAKE_SOURCE_DIR}/config")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/config
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
        COMMENT "Copying config directory"
    )
endif()

# =========================
# SQL init script copy (optional)
# =========================
set(SQL_INIT_FILE "${CMAKE_SOURCE_DIR}/db/init/001_init.sql")

if(EXISTS "${SQL_INIT_FILE}")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/db/init"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SQL_INIT_FILE}"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/db/init/001_init.sql"
        COMMENT "Copying SQL initialization script to db/init/"
    )
    
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SQL_INIT_FILE}"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/001_init.sql"
        COMMENT "Copying SQL script to exe directory"
    )
endif()