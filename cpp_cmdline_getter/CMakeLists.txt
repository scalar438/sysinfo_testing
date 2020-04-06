project(cmdline_getter)

add_executable(cmdline_getter main.c ph_funcs.c ph_variables.c)
target_link_libraries(cmdline_getter PRIVATE ntdll.lib)