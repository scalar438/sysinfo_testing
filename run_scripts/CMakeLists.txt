project(tester)
cmake_minimum_required(VERSION 3.10)

add_executable(main main.cpp handle.hpp)
set_property(TARGET main PROPERTY CXX_STANDARD 17)