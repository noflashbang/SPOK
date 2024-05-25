
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PARENT_DIR)

set( externHeadersCore 
    ${PARENT_DIR}/include/SPOK/SPOKCore.h
    ${PARENT_DIR}/include/SPOK/SPOKApiTypes.h
    ${PARENT_DIR}/include/SPOK/SPOKNonce.h
    ${PARENT_DIR}/include/SPOK/SPOKBlob.h
    ${PARENT_DIR}/include/SPOK/SPOKPcrs.h
    ${PARENT_DIR}/include/SPOK/BCryptUtil.h
    ${PARENT_DIR}/include/SPOK/NCryptUtil.h
    ${PARENT_DIR}/include/SPOK/HasherUtil.h
)

set( externHeadersClient
    ${PARENT_DIR}/include/SPOKClient/SPOKClientApi.h
)

set( externHeadersServer
    ${PARENT_DIR}/include/SPOKServer/SPOKServerApi.h
)

set( toolSource 
   ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/src/stdlib.h
   ${CMAKE_CURRENT_SOURCE_DIR}/src/util.h
   ${CMAKE_CURRENT_SOURCE_DIR}/src/ArgumentParser.h
   ${CMAKE_CURRENT_SOURCE_DIR}/src/ArgumentParser.cpp

   ${CMAKE_CURRENT_SOURCE_DIR}/src/Action/ISPOKAction.h
   ${CMAKE_CURRENT_SOURCE_DIR}/src/Action/CreateAikAction.h
   ${CMAKE_CURRENT_SOURCE_DIR}/src/Action/CreateAikAction.cpp
)

add_executable(SPOKTool ${toolSource} ${externHeaders})
target_link_libraries(SPOKTool PUBLIC SPOKClient)
target_link_libraries(SPOKTool PUBLIC SPOKServer)

add_dependencies(SPOKTool SPOKClient)
add_dependencies(SPOKTool SPOKServer)

target_include_directories( SPOKTool	PUBLIC ${PARENT_DIR}/SPOK/include/SPOK )
target_include_directories( SPOKTool	PUBLIC ${PARENT_DIR}/SPOK/include/SPOKClient )
target_include_directories( SPOKTool	PUBLIC ${PARENT_DIR}/SPOK/include/SPOKServer )

target_sources( SPOKTool PRIVATE 
    ${toolSource}
 )

 install(TARGETS SPOKTool
        RUNTIME           
          COMPONENT Runtime
          DESTINATION tool
)
install(FILES $<TARGET_RUNTIME_DLLS:SPOKTool> DESTINATION tool)