cmake_minimum_required(VERSION 3.10)
project(merkle_tree)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall -Wextra -Werror -Wpedantic -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all)
add_link_options(-fsanitize=address -fsanitize=undefined)

find_package(Catch2 3 REQUIRED)
add_executable(tests merkle_tree_tests.cpp merkle_tree.hpp merkle_tree.cpp merkle_tree_exceptions.hpp)
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)
