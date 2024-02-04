
add_compile_definitions(SPOKCLIENT_EXPORTS)

cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PARENT_DIR)

set( externHeaders 
    ${PARENT_DIR}/include/SPOKClient/SPOKClientApi.h
)

set( externHeadersCore 
    ${PARENT_DIR}/include/SPOK/SPOKCore.h
)

set( libHeaders 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/StandardLib.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Util.h
)

set( libSource
	${CMAKE_CURRENT_SOURCE_DIR}/src/SPOKClientApi.cpp
)

add_library (SPOKClient SHARED ${libSource} ${libHeaders} ${externHeaders}) 
target_include_directories( SPOKClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/SPOK )
target_include_directories( SPOKClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/SPOKClient )
target_include_directories( SPOKClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src )

target_sources( SPOKClient PRIVATE ${libSource} ${libHeaders} )

target_sources( SPOKClient PUBLIC FILE_SET HEADERS BASE_DIRS ${PARENT_DIR}/include/SPOKClient FILES ${externHeaders} )
target_sources( SPOKClient PUBLIC FILE_SET HEADERS BASE_DIRS ${PARENT_DIR}/include/SPOK FILES ${externHeadersCore} )

install(TARGETS SPOKClient
        RUNTIME DESTINATION bin          
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        FILE_SET HEADERS COMPONENT Development
)
