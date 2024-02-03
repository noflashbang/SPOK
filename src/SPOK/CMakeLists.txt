
add_compile_definitions(AUTOSET_EXPORTS)

cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PARENT_DIR)

set( externHeaders 
    ${PARENT_DIR}/include/SPOK/SPOKApi.h
    ${PARENT_DIR}/include/SPOK/SPOKCore.h
)

set( libHeaders 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/StandardLib.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Util.h
)

set( libSource
	${CMAKE_CURRENT_SOURCE_DIR}/src/SPOKApi.cpp
)

add_library (SPOK SHARED ${libSource} ${libHeaders} ${externHeaders}) 
target_include_directories( SPOK PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/SPOK )
target_include_directories( SPOK PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src )

target_sources( SPOK PRIVATE ${libSource} ${libHeaders} )

target_sources( SPOK PUBLIC FILE_SET HEADERS BASE_DIRS ${PARENT_DIR}/include/SPOK FILES ${externHeaders} )

install(TARGETS SPOK
        RUNTIME DESTINATION bin          
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        FILE_SET HEADERS COMPONENT Development
)
