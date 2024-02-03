

Include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.5.2 # or a later release
)

FetchContent_MakeAvailable(Catch2)



cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PARENT_DIR)

set( externHeaders 
	${PARENT_DIR}/include/SPOK/SPOKApi.h
    ${PARENT_DIR}/include/SPOK/SPOKCore.h
)

set( testSource 
   ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
)

add_executable(SPOKTest ${testSource} ${externHeaders})
target_link_libraries(SPOKTest PRIVATE Catch2::Catch2WithMain)
target_link_libraries(SPOKTest PUBLIC SPOK)

add_dependencies(SPOKTest SPOK)

target_include_directories( SPOKTest	PUBLIC ${PARENT_DIR}/SPOK/include/SPOK )

target_sources( SPOKTest PRIVATE 
    ${testSource}
 )

 install(TARGETS SPOKTest
        RUNTIME           
          COMPONENT Runtime
          DESTINATION test
)
install(FILES $<TARGET_RUNTIME_DLLS:SPOKTest> DESTINATION test)