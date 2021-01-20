# earlier possible? Since we really don't care here
cmake_minimum_required(VERSION 3.0.0)

project(project_for_testing_testcache)

add_library(lib_static STATIC src/lib_src.cpp)
add_library(lib_shared SHARED src/lib_src.cpp)

add_executable(statically_linked_executable src/lib_main.cpp)
add_executable(dynamically_linked_exectutable src/lib_main.cpp)
add_executable(simple_exectutable src/main.cpp)

target_link_libraries(statically_linked_executable lib_static)
target_link_libraries(dynamically_linked_exectutable lib_shared)
