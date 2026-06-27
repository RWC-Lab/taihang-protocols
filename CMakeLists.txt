cmake_minimum_required(VERSION 3.21) # Updated to match Core version requirement
project(taihang_protocols LANGUAGES C CXX)

# --- 1. Settings & Architecture ---
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
    add_compile_options(-O3 -fPIC -Wall -Wno-deprecated-declarations)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        add_compile_options(-maes -msse4.1 -mpclmul -mavx -mavx2 -mrdseed)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64|ARM64")
        add_compile_options(-march=armv8-a+crypto+simd)
    endif()
endif()

# --- 2. Dependencies ---

if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/openssl" "/usr/local/opt/openssl")
endif()

find_package(OpenMP REQUIRED)
find_package(OpenSSL REQUIRED)
# Explicitly find GTest for this project's tests
find_package(GTest REQUIRED)

# --- 3. Integrate Taihang Core (Side-by-Side) ---

# Calculate absolute path to sibling directory
get_filename_component(TAIHANG_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../taihang" ABSOLUTE)

if(EXISTS "${TAIHANG_CORE_DIR}/CMakeLists.txt")
    message(STATUS "Taihang-Protocols: Integrating Core Source from ${TAIHANG_CORE_DIR}")
    
    # OPTION: Disable Core's internal tests to speed up the Protocol build
    set(TAIHANG_BUILD_TESTS OFF CACHE BOOL "Disable Core tests" FORCE)
    
    # Add Core to the build. This makes targets 'taihang' and 'taihang::taihang' available.
    add_subdirectory("${TAIHANG_CORE_DIR}" "${CMAKE_BINARY_DIR}/taihang_core_build")
else()
    message(FATAL_ERROR "Taihang Core not found at ${TAIHANG_CORE_DIR}. Ensure folders are side-by-side.")
endif()

# --- 4. Library Definition ---

file(GLOB_RECURSE PROTOCOL_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

add_library(taihang_protocols STATIC ${PROTOCOL_SOURCES})

target_include_directories(taihang_protocols PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# === CRITICAL FIX ===
# Link against the ALIAS target 'taihang::taihang' defined in the Core CMake.
# This ensures include paths AND the binary libtaihang.a are propagated correctly.
target_link_libraries(taihang_protocols PUBLIC 
    taihang::taihang 
    OpenMP::OpenMP_CXX
)

# --- 5. Test Suite ---

enable_testing()
include(GoogleTest)

file(GLOB TEST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.cpp")

foreach(test_source ${TEST_FILES})
    get_filename_component(test_name ${test_source} NAME_WE)
    
    add_executable(${test_name} ${test_source})
    
    # Link Protocols (which pulls in Core automatically via PUBLIC linkage above)
    # Link GTest main explicitly
    target_link_libraries(${test_name} PRIVATE 
        taihang_protocols 
        GTest::gtest_main
    )
    
    gtest_discover_tests(${test_name})
endforeach()

# --- 6. Benchmarks ---

file(GLOB BENCH_FILES "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/bench_*.cpp")

foreach(bench_source ${BENCH_FILES})
    get_filename_component(bench_name ${bench_source} NAME_WE)
    add_executable(${bench_name} ${bench_source})
    target_link_libraries(${bench_name} PRIVATE taihang_protocols)
endforeach()

# --- 7. Output Management ---

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)