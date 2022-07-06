
project(Keyfactor-CAgent)

cmake_minimum_required(VERSION 3.16)

set(
        kf_cagent_src
        ${CMAKE_SOURCE_DIR}/config.c
        ${CMAKE_SOURCE_DIR}/csr.c
        ${CMAKE_SOURCE_DIR}/dto.c
        ${CMAKE_SOURCE_DIR}/enrollment.c
        ${CMAKE_SOURCE_DIR}/fetchlogs.c
        ${CMAKE_SOURCE_DIR}/httpclient.c
        ${CMAKE_SOURCE_DIR}/inventory.c
        ${CMAKE_SOURCE_DIR}/logging.c
        ${CMAKE_SOURCE_DIR}/management.c
        ${CMAKE_SOURCE_DIR}/schedule.c
        ${CMAKE_SOURCE_DIR}/serialize.c
        ${CMAKE_SOURCE_DIR}/session.c
        ${CMAKE_SOURCE_DIR}/utils.c
        ${CMAKE_SOURCE_DIR}/lib/base64.c
        ${CMAKE_SOURCE_DIR}/lib/json.c
)

# Configuration options
# Use the -D argument on command line
option(
        OPENTEST
        "Set to compile the OpenSSL build"
        false
)
option(
        WOLFTEST
        "Set to compile the WolfSSL build"
        false
)
option(
        GNUTLSTEST
        "Set to compile the GNU TLS build"
        false
)

message(STATUS "#### Build Configuration ####")
message(STATUS "OPENTEST: ${OPENTEST}")
message(STATUS "WOLFTEST: ${WOLFTEST}")
message(STATUS "GNUTLSTEST: ${GNUTLSTEST}")

# Add primary executable for agent
add_executable(agent agent.c ${kf_cagent_src})

# The only directory needed is the current one; there aren't any other CMakeLists.txt files
# to account for.
set(kf_cagent_includes PUBLIC ${CMAKE_SOURCE_DIR})
target_include_directories(
        agent
        PUBLIC
        ${kf_cagent_includes}
)

# All builds require curl, link these libraries
target_link_libraries(agent PUBLIC curl)

# Apply build configuration
if (OPENTEST)
    target_compile_definitions(
            agent
            PRIVATE
            __OPEN_SSL__
    )
    target_link_libraries(agent PUBLIC crypto)
    target_sources(agent PRIVATE openssl_wrapper/openssl_wrapper.c)
elseif (WOLFTEST)
    target_compile_definitions(
            agent
            PRIVATE
            __WOLF_SSL__
    )
    target_link_libraries(agent PUBLIC wolfssl)
    target_sources(agent PRIVATE wolfssl_wrapper/wolfssl_wrapper.c)
elseif (GNUTLSTEST)
    find_package(GnuTLS "3.6.0" REQUIRED)
    target_compile_definitions(
            agent
            PRIVATE
            __GNU_TLS__
    )
    target_link_libraries(agent PRIVATE GnuTLS)
    target_sources(agent PRIVATE gnutls_wrapper/gnutls_wrapper.c)
    add_subdirectory(gnutls_wrapper/test)
else()
    message(FATAL_ERROR "You must specify a build type. Use the -G flag followed by the name of the crypto lib requested.")
endif()

# Set compile options for build
#target_compile_options(
#        agent
#        PRIVATE
#        -Wall
#        -Wextra
#        -Werror
#        -Wno-missing-field-initializers
#        -Wno-missing-braces
#        -fno-strict-aliasing
#        -Wno-ignored-qualifiers
#)

# CAgent requires that the config.json file be in the binary directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

# CAgent requires that the certs directory be located in the binary directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs DESTINATION ${CMAKE_CURRENT_BINARY_DIR})