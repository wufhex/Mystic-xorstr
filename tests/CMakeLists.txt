cmake_minimum_required(VERSION 3.10)
project(MysticXorstrTests)

set(CXX_STANDARD 17)
set(CXX_STANDARD_REQUIRED true)

# Set the project root 
get_filename_component(PROJ_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

# Add the executable
add_executable(example example.cpp)

# Include the project's include directory
target_include_directories(example PRIVATE "${PROJ_ROOT}/include")

# Add compile options
# Use SSE_AVAILABLE + -msse4.2 to use SSE.
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(example PRIVATE -Wall -Wextra -mavx2)
endif()
target_compile_definitions(example PRIVATE AVX_AVAILABLE=1)
