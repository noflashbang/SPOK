
cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH PARENT_DIR)

set( externHeadersCore 
    ${PARENT_DIR}/include/SPOK/SPOKCore.h
    ${PARENT_DIR}/include/SPOK/SPOKApiTypes.h
    ${PARENT_DIR}/include/SPOK/SPOKNonce.h
    ${PARENT_DIR}/include/SPOK/SPOKBlob.h
    ${PARENT_DIR}/include/SPOK/SPOKPcrs.h
    ${PARENT_DIR}/include/SPOK/NCryptUtil.h
    ${PARENT_DIR}/include/SPOK/BCryptUtil.h
    ${PARENT_DIR}/include/SPOK/HasherUtil.h
    ${PARENT_DIR}/include/SPOK/TPM_20.h
)

set( libHeaders 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/StandardLib.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Util.h
)

set( libSource
	${CMAKE_CURRENT_SOURCE_DIR}/src/SPOKCore.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/SPOKBlob.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/SPOKPcrs.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/NCryptUtil.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/BCryptUtil.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/HasherUtil.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/TPM_20.cpp
)

add_library (SPOKCore STATIC ${libSource} ${libHeaders} ${externHeaders}) 
target_include_directories( SPOKCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/SPOK )
target_include_directories( SPOKCore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src )

target_sources( SPOKCore PRIVATE ${libSource} ${libHeaders} )

target_sources( SPOKCore PUBLIC FILE_SET HEADERS BASE_DIRS ${PARENT_DIR}/include/SPOK FILES ${externHeadersCore} )

target_link_libraries( SPOKCore PUBLIC bcrypt.lib ncrypt.lib tbs.lib )

install(TARGETS SPOKCore
        RUNTIME DESTINATION bin          
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        FILE_SET HEADERS COMPONENT Development
)
