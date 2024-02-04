
add_compile_definitions(SPOKSERVER_EXPORTS)

cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PARENT_DIR)

set( externHeaders 
    ${PARENT_DIR}/include/SPOKServer/SPOKServerApi.h
)

set( externHeadersCore 
    ${PARENT_DIR}/include/SPOK/SPOKCore.h
)

set( libHeaders 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/StandardLib.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Util.h
)

set( libSource
	${CMAKE_CURRENT_SOURCE_DIR}/src/SPOKServerApi.cpp
)

add_library (SPOKServer SHARED ${libSource} ${libHeaders} ${externHeaders}) 
target_include_directories( SPOKServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/SPOK )
target_include_directories( SPOKServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/SPOKServer )
target_include_directories( SPOKServer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src )

target_sources( SPOKServer PRIVATE ${libSource} ${libHeaders} )

target_sources( SPOKServer PUBLIC FILE_SET HEADERS BASE_DIRS ${PARENT_DIR}/include/SPOKServer FILES ${externHeaders} )
target_sources( SPOKServer PUBLIC FILE_SET HEADERS BASE_DIRS ${PARENT_DIR}/include/SPOK FILES ${externHeadersCore} )

target_link_libraries(SPOKServer PUBLIC SPOKCore)
add_dependencies(SPOKServer SPOKCore)

install(TARGETS SPOKServer
        RUNTIME DESTINATION bin          
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        FILE_SET HEADERS COMPONENT Development
)
