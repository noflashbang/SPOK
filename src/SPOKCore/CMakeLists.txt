
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PARENT_DIR)

set( externHeadersCore 
    ${PARENT_DIR}/include/SPOK/SPOKCore.h
)

set( libHeaders 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/StandardLib.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Util.h
)

set( libSource
	${CMAKE_CURRENT_SOURCE_DIR}/src/SPOKCore.cpp
)

add_library (SPOKCore STATIC ${libSource} ${libHeaders} ${externHeaders}) 
target_include_directories( SPOKCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/SPOK )
target_include_directories( SPOKCore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src )

target_sources( SPOKCore PRIVATE ${libSource} ${libHeaders} )

target_sources( SPOKCore PUBLIC FILE_SET HEADERS BASE_DIRS ${PARENT_DIR}/include/SPOK FILES ${externHeadersCore} )

install(TARGETS SPOKCore
        RUNTIME DESTINATION bin          
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        FILE_SET HEADERS COMPONENT Development
)
