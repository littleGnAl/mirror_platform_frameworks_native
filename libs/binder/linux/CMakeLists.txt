cmake_minimum_required(VERSION 3.18)

project(libbinder CXX)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(AppendCxxFlagIfSupported)

set(CMAKE_CXX_STANDARD 20)

set(LIBBINDER_CXX_FLAGS
    "-Wall"
    "-Wextra"
    "-fPIC"
    "-Wno-attributes"
    "-Wno-unknown-pragmas"
    "-Wno-missing-field-initializers"
    "-Wno-strict-aliasing"
    "-Wno-unused-variable"
    "-Wno-deprecated"
    "-Wno-sign-compare"
    "-Wno-sequence-point"
    "-Wno-pessimizing-move"
    "-Wno-unused-result"
    "-Wno-format"
    "-Wno-psabi"
)

append_cxx_flag_if_supported(-Wno-stringop-overread LIBBINDER_CXX_FLAGS)
append_cxx_flag_if_supported(-Wno-restrict LIBBINDER_CXX_FLAGS)
append_cxx_flag_if_supported(-Wno-subobject-linkage LIBBINDER_CXX_FLAGS)
append_cxx_flag_if_supported(-Wno-class-memaccess LIBBINDER_CXX_FLAGS)
append_cxx_flag_if_supported(-Wno-reorder-init-list LIBBINDER_CXX_FLAGS)

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
)

add_subdirectory(libbase)
add_subdirectory(libutils)

add_library(android_libbinder ${LIBBINDER_SRCS})
target_include_directories(android_libbinder
    PUBLIC
    "${LIBBINDER_DIR}/include"
)
target_link_libraries(android_libbinder android_libbase android_libutils ssl)
target_compile_options(android_libbinder
    PRIVATE
    ${LIBBINDER_CXX_FLAGS}
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
