CMAKE_MINIMUM_REQUIRED(VERSION 3.4)
PROJECT(cryptotest)

######################################################################
# 	Openssl stuff
######################################################################

SET(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../install)
MESSAGE(STATUS "OPENSSL_INSTALL_DIR = ${OPENSSL_INSTALL_DIR}")

FIND_PATH(OPENSSL_INCLUDE_DIR
	NAMES openssl/opensslconf.h
	PATHS ${OPENSSL_INSTALL_DIR}/include
	NO_DEFAULT_PATH)

FIND_LIBRARY(OPENSSL_LIBRARY
	NAMES libcrypto.dylib
	PATHS ${OPENSSL_INSTALL_DIR}/lib
	NO_DEFAULT_PATH)

MESSAGE(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
MESSAGE(STATUS "OPENSSL_LIBRARY = ${OPENSSL_LIBRARY}")

if(NOT OPENSSL_INCLUDE_DIR)
	MESSAGE(FATAL_ERROR "OPENSSL_INCLUDE_DIR couldnt be found at ${OPENSSL_INSTALL_DIR}/incude/")
else()
	MESSAGE(STATUS "OPENSSL_INCLUDE_DIR is found at ${OPENSSL_INCLUDE_DIR}")
endif()


if(NOT OPENSSL_LIBRARY)
	MESSAGE(FATAL_ERROR "OPENSSL_LIBRARY couldnt be found at ${OPENSSL_INSTALL_DIR}/lib/")
else()
	MESSAGE(STATUS "OPENSSL_LIBRARY is found at ${OPENSSL_LIBRARY}")
endif()

######################################################################
# 	AES GCM stuff
######################################################################
FILE(GLOB AESGCM_SOURCES aesgcm.c fops.c)
ADD_EXECUTABLE(aesgcm
	${AESGCM_SOURCES})

TARGET_LINK_LIBRARIES(aesgcm
	${OPENSSL_LIBRARY})

TARGET_INCLUDE_DIRECTORIES(aesgcm
	PUBLIC
	${OPENSSL_INCLUDE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR})

SET_TARGET_PROPERTIES(aesgcm
	PROPERTIES
	COMPILE_FLAGS
	"-Wall")

######################################################################
# 	Run target
######################################################################
ADD_CUSTOM_TARGET(run
	COMMAND ./aesgcm
	DEPENDS aesgcm
	WORKING_DIRECTORY ${CMAKE_PRJECT_DIR})
