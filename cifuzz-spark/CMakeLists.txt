add_compile_options(-O0 -g)

#cifuzz:build-template:begin
#add_fuzz_test({{ .FuzzTestName }} {{ .FileName }})
#target_link_libraries({{ .FuzzTestName }} PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,Threads::Threads>" PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,csp>")
#cifuzz:build-template:end
add_fuzz_test(fuzz_csp_route_work fuzz_csp_route_work.cpp)
target_link_libraries(fuzz_csp_route_work PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,Threads::Threads>" PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,csp>")
add_fuzz_test(fuzz_csp_service_handler fuzz_csp_service_handler.cpp)
target_link_libraries(fuzz_csp_service_handler PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,Threads::Threads>" PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,csp>")


add_fuzz_test(fuzz_test fuzz_test.cpp)
target_link_libraries(fuzz_test PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,Threads::Threads>" PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,csp>")

add_fuzz_test(fuzz_test_2 fuzz_test_2.cpp)
target_link_libraries(fuzz_test_2 PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,Threads::Threads>" PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,csp>")
