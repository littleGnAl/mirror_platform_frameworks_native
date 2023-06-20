project(libbinder CXX)

set(CMAKE_CXX_STANDARD 17)

set(LIBBINDER_CXX_FLAGS
    "-Wall"
    "-Werror"
    "-Wextra"
    "-Wno-error=deprecated-declarations"
    "-fPIC"
)

if (NOT LIBBINDER_DIR AND ANDROID_BUILD_TOP)
    set(LIBBINDER_DIR "${ANDROID_BUILD_TOP}/frameworks/native/libs/binder")
endif()

if (NOT BORINGSSL_DIR AND ANDROID_BUILD_TOP)
    set(BORINGSSL_DIR "${ANDROID_BUILD_TOP}/external/boringssl")
endif()

add_subdirectory("${BORINGSSL_DIR}" boringssl EXCLUDE_FROM_ALL)

set(LIBBINDER_SRCS
    "${LIBBINDER_DIR}/Binder.cpp"
    "${LIBBINDER_DIR}/BpBinder.cpp"
    "${LIBBINDER_DIR}/Debug.cpp"
    "${LIBBINDER_DIR}/FdTrigger.cpp"
    "${LIBBINDER_DIR}/IInterface.cpp"
    "${LIBBINDER_DIR}/IResultReceiver.cpp"
    "${LIBBINDER_DIR}/OS.cpp"
    "${LIBBINDER_DIR}/Parcel.cpp"
    "${LIBBINDER_DIR}/ParcelFileDescriptor.cpp"
    "${LIBBINDER_DIR}/RecordedTransaction.cpp"
    "${LIBBINDER_DIR}/RpcSession.cpp"
    "${LIBBINDER_DIR}/RpcServer.cpp"
    "${LIBBINDER_DIR}/RpcState.cpp"
    "${LIBBINDER_DIR}/RpcTransportRaw.cpp"
    "${LIBBINDER_DIR}/Stability.cpp"
    "${LIBBINDER_DIR}/Status.cpp"
    "${LIBBINDER_DIR}/TextOutput.cpp"
    "${LIBBINDER_DIR}/Trace.cpp"
    "${LIBBINDER_DIR}/Utils.cpp"
    "${LIBBINDER_DIR}/trusty/RpcServerTrusty.cpp"
    "${LIBBINDER_DIR}/trusty/RpcTransportTipcTrusty.cpp"
    "${LIBBINDER_DIR}/trusty/TrustyStatus.cpp"
)

add_subdirectory(libbase)
add_subdirectory(libutils)

add_library(android_libbinder ${LIBBINDER_SRCS})
target_include_directories(android_libbinder
    PUBLIC
        "${LIBBINDER_DIR}/include"
        "${LIBBINDER_DIR}/trusty/include"
        "${LIBBINDER_DIR}/trusty"
)
target_link_libraries(android_libbinder android_libbase android_libutils ssl)
target_compile_options(android_libbinder
    PRIVATE
    ${LIBBINDER_CXX_FLAGS}
    "-DTRUSTY_USERSPACE"
)

set(LIBBINDER_TLS_SRCS
    "${LIBBINDER_DIR}/RpcTransportTls.cpp"
    "${LIBBINDER_DIR}/RpcTlsUtils.cpp"
)

add_library(android_libbinder_tls "${LIBBINDER_TLS_SRCS}")
target_include_directories(android_libbinder_tls
    PUBLIC
    "${LIBBINDER_DIR}/include_tls")
target_link_libraries(android_libbinder_tls
    android_libbase
    android_liblog
    android_libbinder
    android_libutils
    ssl
    crypto
)
target_compile_options(android_libbinder_tls PRIVATE ${LIBBINDER_CXX_FLAGS})

if (NOT AIDL_BIN)
    find_program(AIDL_BIN aidl REQUIRED)
endif()
set(LIBBINDER_TEST_AIDL_SRCS
    "${LIBBINDER_DIR}/tests/BinderRpcTestClientInfo.aidl"
    "${LIBBINDER_DIR}/tests/BinderRpcTestServerConfig.aidl"
    "${LIBBINDER_DIR}/tests/BinderRpcTestServerInfo.aidl"
    "${LIBBINDER_DIR}/tests/IBinderRpcCallback.aidl"
    "${LIBBINDER_DIR}/tests/IBinderRpcSession.aidl"
    "${LIBBINDER_DIR}/tests/IBinderRpcTest.aidl"
    "${LIBBINDER_DIR}/tests/ParcelableCertificateData.aidl"
)
set(LIBBINDER_TEST_AIDL_GENDIR "${PROJECT_BINARY_DIR}/gens")
set(LIBBINDER_TEST_AIDL_GEN_SRCS)
foreach(AIDL_FILE ${LIBBINDER_TEST_AIDL_SRCS})
    get_filename_component(ABS_AIDL_FILEPATH ${AIDL_FILE} ABSOLUTE)
    get_filename_component(ABS_AIDL_DIR ${ABS_AIDL_FILEPATH} DIRECTORY)
    get_filename_component(AIDL_FILENAME ${AIDL_FILE} NAME)
    get_filename_component(AIDL_FILENAME_WE ${AIDL_FILE} NAME_WE)
    set(AIDL_CPP_FILE "${LIBBINDER_TEST_AIDL_GENDIR}/${AIDL_FILENAME_WE}.cpp")
    add_custom_command(
        OUTPUT "${AIDL_CPP_FILE}"
        COMMAND "${AIDL_BIN}"
        ARGS
        --lang=cpp
        -Weverything
        -Wno-missing-permission-annotation
        -Wno-mixed-oneway
        -Werror
        -t
        --min_sdk_version current
        --structured
        --ninja
        -d "${LIBBINDER_TEST_AIDL_GENDIR}/${AIDL_FILENAME_WE}.cpp.d"
        -h "${LIBBINDER_TEST_AIDL_GENDIR}/include"
        -o "${LIBBINDER_TEST_AIDL_GENDIR}"
        -I "${ABS_AIDL_DIR}"
        "${AIDL_FILE}"
    )
list(APPEND LIBBINDER_TEST_AIDL_GEN_SRCS "${AIDL_CPP_FILE}")
endforeach()

add_library(android_libbinder_ndk_hdrs INTERFACE)
target_include_directories(android_libbinder_ndk_hdrs INTERFACE
    "${LIBBINDER_DIR}/ndk/include_cpp"
    "${LIBBINDER_DIR}/ndk/include_ndk"
    "${LIBBINDER_DIR}/ndk/include_platform"
)

add_library(android_libbinder_test_aidl ${LIBBINDER_TEST_AIDL_GEN_SRCS})
target_include_directories(android_libbinder_test_aidl
    PUBLIC
    "${LIBBINDER_TEST_AIDL_GENDIR}/include"
)
target_link_libraries(android_libbinder_test_aidl
    android_libbinder
    android_libbinder_ndk_hdrs
)

add_library(android_libbinder_tls_test_utils
    "${LIBBINDER_DIR}/tests/RpcTlsTestUtils.cpp"
)
target_include_directories(android_libbinder_tls_test_utils
    PUBLIC
    "${LIBBINDER_DIR}/tests/include_tls_test_utils"
)
target_link_libraries(android_libbinder_tls_test_utils
    android_libbinder
    android_libbinder_tls
)
target_compile_options(android_libbinder_tls_test_utils
    PRIVATE
    ${LIBBINDER_CXX_FLAGS}
)

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

set(LIBBINDER_TEST_COMMON_DEPS
    android_libbinder
    android_libbinder_ndk_hdrs
    android_libbinder_tls
    android_libbinder_tls_test_utils
    android_libbinder_test_aidl
)

set(LIBBINDER_TESTSERVICE_SRCS
    "${LIBBINDER_DIR}/tests/binderRpcTestCommon.cpp"
    "${LIBBINDER_DIR}/tests/binderRpcTestService.cpp"
)
add_executable(binder_rpc_test_service_no_kernel ${LIBBINDER_TESTSERVICE_SRCS})
target_include_directories(binder_rpc_test_service_no_kernel
    PRIVATE
    "${LIBBINDER_DIR}/tests"
)
target_link_libraries(binder_rpc_test_service_no_kernel
    ${LIBBINDER_TEST_COMMON_DEPS}
)
target_compile_options(binder_rpc_test_service_no_kernel
    PRIVATE
    ${LIBBINDER_CXX_FLAGS}
    "-Wno-error=sign-compare"
)

set(LIBBINDER_TEST_SRCS
    "${LIBBINDER_DIR}/tests/binderRpcUniversalTests.cpp"
    "${LIBBINDER_DIR}/tests/binderRpcTestCommon.cpp"
    "${LIBBINDER_DIR}/tests/binderRpcTest.cpp"
)
add_executable(binder_rpc_test ${LIBBINDER_TEST_SRCS})
target_include_directories(binder_rpc_test
    PRIVATE
    "${LIBBINDER_DIR}/tests"
)
target_link_libraries(binder_rpc_test
    ${LIBBINDER_TEST_COMMON_DEPS}
    GTest::gtest)
target_compile_options(binder_rpc_test
    PRIVATE
    ${LIBBINDER_CXX_FLAGS}
    "-Wno-error=pessimizing-move"
    "-Wno-error=sign-compare"
    "-Wno-error=reorder-init-list"
    "-D__ANDROID_VENDOR__"
)
gtest_discover_tests(binder_rpc_test)
