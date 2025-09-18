cmake_minimum_required(VERSION 3.18.1)

project("encrypted_root_engine")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIRS})

# Add the native library
add_library(
    encrypted_root_engine
    SHARED
    EncryptedRootEngine.cpp
)

# Link libraries
target_link_libraries(
    encrypted_root_engine
    ${OPENSSL_LIBRARIES}
    log
    android
)

# Compiler flags
target_compile_options(encrypted_root_engine PRIVATE
    -Wall
    -Wextra
    -O2
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)

# Linker flags
target_link_options(encrypted_root_engine PRIVATE
    -Wl,--strip-all
    -Wl,--gc-sections
)

# Set output directory
set_target_properties(encrypted_root_engine PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../libs
)
