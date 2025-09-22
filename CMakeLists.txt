cmake_minimum_required(VERSION 3.16)
project(RawrZApp VERSION 1.0.0 LANGUAGES C CXX ASM)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build configuration options
option(BUILD_TESTS "Build test executables" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(STATIC_BUILD "Build static executables" OFF)

# Platform detection
if(WIN32)
    set(PLATFORM_WINDOWS TRUE)
elseif(APPLE)
    set(PLATFORM_MACOS TRUE)
elseif(UNIX)
    set(PLATFORM_LINUX TRUE)
endif()

# Architecture detection
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(ARCH_X86_64 TRUE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(ARCH_ARM64 TRUE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM")
    set(ARCH_ARM32 TRUE)
endif()

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3 -DNDEBUG)
    endif()
endif()

# Sanitizer flags
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

if(ENABLE_TSAN)
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
endif()

if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

# Coverage flags
if(ENABLE_COVERAGE)
    add_compile_options(-fprofile-arcs -ftest-coverage)
    add_link_options(-lgcov --coverage)
endif()

# Static build
if(STATIC_BUILD)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Source files for Reverser language components
set(REVERSER_SOURCES
    reverser_lexer.asm
    reverser_ast.asm
    reverser_parser.asm
    reverser_runtime.asm
    reverser_bytecode_gen.asm
    reverser_vtable.asm
    reverser_platform.asm
    reverser_syscalls.asm
)

# Source files for Eon template generator
set(TEMPLATE_GENERATOR_SOURCES
    eon_template_lexer.asm
    eon_template_parser.asm
    eon_template_engine.asm
    uim_model.asm
    data_source_adapters.asm
    eon_template_generator.asm
)

# Source files for Eon compiler (C implementation)
set(EON_C_SOURCES
    eon_compiler.c
    eon_llvm_compiler.c
)

# Create object files from assembly sources
if(ARCH_X86_64)
    enable_language(ASM_NASM)
    set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)
    if(PLATFORM_WINDOWS)
        set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
    elseif(PLATFORM_MACOS)
        set(CMAKE_ASM_NASM_OBJECT_FORMAT macho64)
    endif()
endif()

# Reverser lexer executable
add_executable(reverser_lexer
    reverser_lexer.asm
    test_reverser_lexer.asm
)

# Reverser parser executable  
add_executable(reverser_parser
    reverser_lexer.asm
    reverser_ast.asm
    reverser_parser.asm
    test_reverser_parser.asm
)

# Reverser runtime test executable
add_executable(reverser_runtime_test
    reverser_runtime.asm
    reverser_bytecode_gen.asm
    test_reverser_runtime.asm
)

# Reverser vtable test executable
add_executable(reverser_vtable_test
    reverser_vtable.asm
    reverser_runtime.asm
    test_reverser_vtable.asm
)

# Reverser bootstrap compiler
add_executable(reverser_bootstrap
    reverser_lexer.asm
    reverser_parser.asm
    reverser_runtime.asm
    bootstrap_reverser.asm
)

# Eon compiler (C version)
add_executable(eon_compiler
    eon_compiler.c
)
target_link_libraries(eon_compiler pthread)

# Eon LLVM compiler (C version)
add_executable(eon_llvm_compiler
    eon_llvm_compiler.c
)
target_link_libraries(eon_llvm_compiler pthread)

# Eon template generator
add_executable(eon_template_generator
    ${TEMPLATE_GENERATOR_SOURCES}
)

# Template generator test executable
add_executable(template_generator_test
    ${TEMPLATE_GENERATOR_SOURCES}
    test_template_generator.asm
)

# Platform-specific linker settings
if(PLATFORM_LINUX)
    target_link_libraries(reverser_lexer c)
    target_link_libraries(reverser_parser c)
    target_link_libraries(reverser_runtime_test c)
    target_link_libraries(reverser_vtable_test c)
    target_link_libraries(reverser_bootstrap c)
    target_link_libraries(eon_template_generator c)
    target_link_libraries(template_generator_test c)
elseif(PLATFORM_WINDOWS)
    target_link_libraries(reverser_lexer kernel32 user32)
    target_link_libraries(reverser_parser kernel32 user32)
    target_link_libraries(reverser_runtime_test kernel32 user32)
    target_link_libraries(reverser_vtable_test kernel32 user32)
    target_link_libraries(reverser_bootstrap kernel32 user32)
    target_link_libraries(eon_template_generator kernel32 user32)
    target_link_libraries(template_generator_test kernel32 user32)
elseif(PLATFORM_MACOS)
    target_link_libraries(reverser_lexer System)
    target_link_libraries(reverser_parser System)
    target_link_libraries(reverser_runtime_test System)
    target_link_libraries(reverser_vtable_test System)
    target_link_libraries(reverser_bootstrap System)
    target_link_libraries(eon_template_generator System)
    target_link_libraries(template_generator_test System)
endif()

# Custom target for running all tests
if(BUILD_TESTS)
    add_custom_target(run_tests
        COMMAND reverser_lexer
        COMMAND reverser_parser
        COMMAND reverser_runtime_test
        COMMAND reverser_vtable_test
        COMMAND eon_compiler test_program.eon
        COMMAND eon_llvm_compiler test_program.eon
        DEPENDS reverser_lexer reverser_parser reverser_runtime_test 
                reverser_vtable_test eon_compiler eon_llvm_compiler
        COMMENT "Running all tests"
    )
endif()

# Custom target for building self-hosting compilers
add_custom_target(self_hosting
    COMMAND reverser_bootstrap
    DEPENDS reverser_bootstrap
    COMMENT "Building self-hosting Reverser compiler"
)

# Custom command for template generation
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/generated_data_access.eon
    COMMAND eon_template_generator
    ARGS
        ${CMAKE_CURRENT_SOURCE_DIR}/example_data_access.eont
        ${CMAKE_CURRENT_SOURCE_DIR}/example_schema.json
        ${CMAKE_CURRENT_BINARY_DIR}/generated_data_access.eon
        json
    DEPENDS
        eon_template_generator
        example_data_access.eont
        example_schema.json
    COMMENT "Generating data access code from template"
)

# Custom command for API bindings generation
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/generated_api_bindings.eon
    COMMAND eon_template_generator
    ARGS
        ${CMAKE_CURRENT_SOURCE_DIR}/example_api_bindings.eont
        ${CMAKE_CURRENT_SOURCE_DIR}/example_api_spec.json
        ${CMAKE_CURRENT_BINARY_DIR}/generated_api_bindings.eon
        json
    DEPENDS
        eon_template_generator
        example_api_bindings.eont
        example_api_spec.json
    COMMENT "Generating API bindings from template"
)

# Custom target for template generation
add_custom_target(template_generation
    DEPENDS
        ${CMAKE_CURRENT_BINARY_DIR}/generated_data_access.eon
        ${CMAKE_CURRENT_BINARY_DIR}/generated_api_bindings.eon
    COMMENT "Running template generation"
)

# Installation
install(TARGETS 
    reverser_lexer
    reverser_parser
    reverser_runtime_test
    reverser_vtable_test
    reverser_bootstrap
    eon_compiler
    eon_llvm_compiler
    DESTINATION bin
)

# Install source files for bootstrapping
install(FILES
    reverser_self_compiler.rev
    eon_v1_compiler.eon
    eon_full_compiler.eon
    test_program.eon
    DESTINATION share/rawrzapp
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "RawrZApp")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Bootstrapped Programming Language Compiler Suite")
set(CPACK_PACKAGE_VENDOR "RawrZ Development Team")
set(CPACK_PACKAGE_CONTACT "dev@rawrz.app")

if(PLATFORM_WINDOWS)
    set(CPACK_GENERATOR "ZIP;NSIS")
elseif(PLATFORM_MACOS)
    set(CPACK_GENERATOR "TGZ;DragNDrop")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
endif()

include(CPack)

# Generate compile_commands.json for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Custom targets for different build configurations
add_custom_target(debug
    COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug ${CMAKE_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
    COMMENT "Building debug configuration"
)

add_custom_target(release
    COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Release ${CMAKE_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
    COMMENT "Building release configuration"
)

add_custom_target(profile
    COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=RelWithDebInfo ${CMAKE_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
    COMMENT "Building profile configuration"
)

# Documentation generation with Doxygen (if available)
find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in 
                   ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(docs
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
    )
endif()

# Benchmarking target
add_custom_target(benchmark
    COMMAND echo "Running compiler benchmarks..."
    COMMAND time reverser_bootstrap
    COMMAND time eon_compiler test_program.eon
    COMMAND time eon_llvm_compiler test_program.eon
    DEPENDS reverser_bootstrap eon_compiler eon_llvm_compiler
    COMMENT "Running performance benchmarks"
)

# Clean target for removing generated files
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}
    COMMENT "Cleaning all build files"
)

# Print build configuration summary
message(STATUS "=== RawrZApp Build Configuration ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "CXX Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "ASM Compiler: ${CMAKE_ASM_COMPILER}")
message(STATUS "Build Tests: ${BUILD_TESTS}")
message(STATUS "Build Examples: ${BUILD_EXAMPLES}")
message(STATUS "Enable ASAN: ${ENABLE_ASAN}")
message(STATUS "Enable Coverage: ${ENABLE_COVERAGE}")
message(STATUS "Static Build: ${STATIC_BUILD}")
message(STATUS "======================================")