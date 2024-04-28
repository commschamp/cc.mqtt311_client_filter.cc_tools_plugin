#!/bin/bash

# Input
# BUILD_DIR - Main build directory
# CC - Main C compiler
# CXX - Main C++ compiler
# CC_COMMSDSL - C compiler for commsdsl
# CXX_COMMSDSL - C++ compiler for commsdsl
# EXTERNALS_DIR - (Optional) Directory where externals need to be located
# COMMS_REPO - (Optional) Repository of the COMMS library
# COMMS_TAG - (Optional) Tag of the COMMS library
# CC_TOOLS_QT_REPO - (Optional) Repository of the cc_tools_qt
# CC_TOOLS_QT_TAG - (Optional) Tag of the cc_tools_qt
# CC_TOOLS_QT_SKIP - (Optional) Skip build of cc_tools_qt
# CC_MQTT311_GENERATED_REPO - (Optional) Repository of the cc.mqtt311.generated
# CC_MQTT311_GENERATED_TAG - (Optional) Tag of the cc.mqtt311.generated
# CC_MQTT311_LIBS_REPO - (Optional) Repository of the cc.mqtt311.libs
# CC_MQTT311_LIBS_TAG - (Optional) Tag of the cc.mqtt311.libs
# COMMON_INSTALL_DIR - (Optional) Common directory to perform installations
# COMMON_BUILD_TYPE - (Optional) CMake build type
# COMMON_CXX_STANDARD - (Optional) CMake C++ standard
# COMMON_CMAKE_GENERATOR - (Optional) CMake generator
# COMMON_CMAKE_PLATFORM - (Optional) CMake platform
# COMMON_QT_VER - (Optional) common Qt major version
# COMMON_USE_CCACHE - (Optional) control of whether to use ccache

#####################################

if [ -z "${BUILD_DIR}" ]; then
    echo "BUILD_DIR hasn't been specified"
    exit 1
fi

if [ -z "${EXTERNALS_DIR}" ]; then
    EXTERNALS_DIR=${BUILD_DIR}/externals
fi

if [ -z "${COMMS_REPO}" ]; then
    COMMS_REPO=https://github.com/commschamp/comms.git
fi

if [ -z "${COMMS_TAG}" ]; then
    COMMS_TAG=master
fi

if [ -z "${CC_TOOLS_QT_REPO}" ]; then
    CC_TOOLS_QT_REPO=https://github.com/commschamp/cc_tools_qt.git
fi

if [ -z "${CC_TOOLS_QT_TAG}" ]; then
    CC_TOOLS_QT_TAG=master
fi

if [ -z "${CC_MQTT311_GENERATED_REPO}" ]; then
    CC_MQTT311_GENERATED_REPO=https://github.com/commschamp/cc.mqtt311.generated.git
fi

if [ -z "${CC_MQTT311_GENERATED_TAG}" ]; then
    CC_MQTT311_GENERATED_TAG=master
fi

if [ -z "${CC_MQTT311_LIBS_REPO}" ]; then
    CC_MQTT311_LIBS_REPO=https://github.com/commschamp/cc.mqtt311.libs.git
fi

if [ -z "${CC_MQTT311_LIBS_TAG}" ]; then
    CC_MQTT311_LIBS_TAG=master
fi

if [ -z "${COMMON_BUILD_TYPE}" ]; then
    COMMON_BUILD_TYPE=Debug
fi

if [ -z "${COMMON_CXX_STANDARD}" ]; then
    COMMON_CXX_STANDARD=17
fi

if [ -z "${COMMON_QT_VER}" ]; then
    COMMON_QT_VER=5
fi

COMMS_SRC_DIR=${EXTERNALS_DIR}/comms
COMMS_BUILD_DIR=${BUILD_DIR}/externals/comms/build
COMMS_INSTALL_DIR=${COMMS_BUILD_DIR}/install
if [ -n "${COMMON_INSTALL_DIR}" ]; then
    COMMS_INSTALL_DIR=${COMMON_INSTALL_DIR}
fi

CC_TOOLS_QT_SRC_DIR=${EXTERNALS_DIR}/cc_tools_qt
CC_TOOLS_QT_BUILD_DIR=${BUILD_DIR}/externals/cc_tools_qt/build
CC_TOOLS_QT_INSTALL_DIR=${CC_TOOLS_QT_BUILD_DIR}/install
if [ -n "${COMMON_INSTALL_DIR}" ]; then
    CC_TOOLS_QT_INSTALL_DIR=${COMMON_INSTALL_DIR}
fi

CC_MQTT311_GENERATED_SRC_DIR=${EXTERNALS_DIR}/cc.mqtt311.generated
CC_MQTT311_GENERATED_BUILD_DIR=${BUILD_DIR}/externals/cc.mqtt311.generated/build
CC_MQTT311_GENERATED_INSTALL_DIR=${CC_MQTT311_GENERATED_BUILD_DIR}/install
if [ -n "${COMMON_INSTALL_DIR}" ]; then
    CC_MQTT311_GENERATED_INSTALL_DIR=${COMMON_INSTALL_DIR}
fi

CC_MQTT311_LIBS_SRC_DIR=${EXTERNALS_DIR}/cc.mqtt311.libs
CC_MQTT311_LIBS_BUILD_DIR=${BUILD_DIR}/externals/cc.mqtt311.libs/build
CC_MQTT311_LIBS_INSTALL_DIR=${CC_MQTT311_LIBS_BUILD_DIR}/install
if [ -n "${COMMON_INSTALL_DIR}" ]; then
    CC_MQTT311_LIBS_INSTALL_DIR=${COMMON_INSTALL_DIR}
fi

procs=$(nproc)
if [ -n "${procs}" ]; then
    procs_param="--parallel ${procs}"
fi

#####################################

function build_comms() {
    local proj_name="COMMS library"
    if [ -e ${COMMS_SRC_DIR}/.git ]; then
        echo "Updating ${proj_name}..."
        cd ${COMMS_SRC_DIR}
        git fetch --all
        git checkout .
        git checkout ${COMMS_TAG}
        git pull --all
    else
        echo "Cloning ${proj_name}..."
        mkdir -p ${EXTERNALS_DIR}
        git clone -b ${COMMS_TAG} ${COMMS_REPO} ${COMMS_SRC_DIR}
    fi

    echo "Building ${proj_name}..."
    mkdir -p ${COMMS_BUILD_DIR}
    cmake -S ${COMMS_SRC_DIR} -B ${COMMS_BUILD_DIR} \
        ${COMMON_CMAKE_GENERATOR:+"-G ${COMMON_CMAKE_GENERATOR}"} ${COMMON_CMAKE_PLATFORM:+"-A ${COMMON_CMAKE_PLATFORM}"} \
        -DCMAKE_INSTALL_PREFIX=${COMMS_INSTALL_DIR} -DCMAKE_BUILD_TYPE=${COMMON_BUILD_TYPE} -DCMAKE_CXX_STANDARD=${COMMON_CXX_STANDARD}
    cmake --build ${COMMS_BUILD_DIR} --config ${COMMON_BUILD_TYPE} --target install ${procs_param}
}

function build_cc_tools_qt() {
    local proj_name="cc_tools_qt"
    if [ -e ${CC_TOOLS_QT_SRC_DIR}/.git ]; then
        echo "Updating ${proj_name}"
        cd ${CC_TOOLS_QT_SRC_DIR}
        git fetch --all
        git checkout .
        git checkout ${CC_TOOLS_QT_TAG}
        git pull --all
    else
        echo "Cloning ${proj_name} ..."
        mkdir -p ${EXTERNALS_DIR}
        git clone -b ${CC_TOOLS_QT_TAG} ${CC_TOOLS_QT_REPO} ${CC_TOOLS_QT_SRC_DIR}
    fi

    echo "Building ${proj_name} ..."
    mkdir -p ${CC_TOOLS_QT_BUILD_DIR}
    cmake -S ${CC_TOOLS_QT_SRC_DIR} -B ${CC_TOOLS_QT_BUILD_DIR} \
        ${COMMON_CMAKE_GENERATOR:+"-G ${COMMON_CMAKE_GENERATOR}"} ${COMMON_CMAKE_PLATFORM:+"-A ${COMMON_CMAKE_PLATFORM}"} \
        -DCMAKE_INSTALL_PREFIX=${CC_TOOLS_QT_INSTALL_DIR} -DCMAKE_BUILD_TYPE=${COMMON_BUILD_TYPE} \
        ${COMMON_USE_CCACHE:+"-DCC_TOOLS_QT_USE_CCACHE=${COMMON_USE_CCACHE}"} \
        -DCC_TOOLS_QT_BUILD_APPS=OFF -DCMAKE_PREFIX_PATH=${COMMS_INSTALL_DIR} \
        -DCMAKE_CXX_STANDARD=${COMMON_CXX_STANDARD} -DCC_TOOLS_QT_MAJOR_QT_VERSION=${COMMON_QT_VER}
    cmake --build ${CC_TOOLS_QT_BUILD_DIR} --config ${COMMON_BUILD_TYPE} --target install ${procs_param}
}

function build_cc_mqtt311_generated() {
    local proj_name="cc.mqtt311.generated"
    if [ -e ${CC_MQTT311_GENERATED_SRC_DIR}/.git ]; then
        echo "Updating ${proj_name}"
        cd ${CC_MQTT311_GENERATED_SRC_DIR}
        git fetch --all
        git checkout .
        git checkout ${CC_MQTT311_GENERATED_TAG}
        git pull --all
    else
        echo "Cloning ${proj_name} ..."
        mkdir -p ${EXTERNALS_DIR}
        git clone -b ${CC_MQTT311_GENERATED_TAG} ${CC_MQTT311_GENERATED_REPO} ${CC_MQTT311_GENERATED_SRC_DIR}
    fi

    echo "Building ${proj_name} ..."
    mkdir -p ${CC_MQTT311_GENERATED_BUILD_DIR}
    cmake -S ${CC_MQTT311_GENERATED_SRC_DIR} -B ${CC_MQTT311_GENERATED_BUILD_DIR} \
        ${COMMON_CMAKE_GENERATOR:+"-G ${COMMON_CMAKE_GENERATOR}"} ${COMMON_CMAKE_PLATFORM:+"-A ${COMMON_CMAKE_PLATFORM}"} \
        -DCMAKE_INSTALL_PREFIX=${CC_MQTT311_GENERATED_INSTALL_DIR} -DCMAKE_BUILD_TYPE=${COMMON_BUILD_TYPE} \
        -DCMAKE_PREFIX_PATH=${COMMS_INSTALL_DIR} -DCMAKE_CXX_STANDARD=${COMMON_CXX_STANDARD} -DOPT_REQUIRE_COMMS_LIB=OFF
    cmake --build ${CC_MQTT311_GENERATED_BUILD_DIR} --config ${COMMON_BUILD_TYPE} --target install ${procs_param}
}

function build_cc_mqtt311_libs() {
    local proj_name="cc.mqtt311.libs"
    if [ -e ${CC_MQTT311_LIBS_SRC_DIR}/.git ]; then
        echo "Updating ${proj_name}"
        cd ${CC_MQTT311_LIBS_SRC_DIR}
        git fetch --all
        git checkout .
        git checkout ${CC_MQTT311_LIBS_TAG}
        git pull --all
    else
        echo "Cloning ${proj_name} ..."
        mkdir -p ${EXTERNALS_DIR}
        git clone -b ${CC_MQTT311_LIBS_TAG} ${CC_MQTT311_LIBS_REPO} ${CC_MQTT311_LIBS_SRC_DIR}
    fi

    echo "Building ${proj_name} ..."
    mkdir -p ${CC_MQTT311_LIBS_BUILD_DIR}
    cmake -S ${CC_MQTT311_LIBS_SRC_DIR} -B ${CC_MQTT311_LIBS_BUILD_DIR} \
        ${COMMON_CMAKE_GENERATOR:+"-G ${COMMON_CMAKE_GENERATOR}"} ${COMMON_CMAKE_PLATFORM:+"-A ${COMMON_CMAKE_PLATFORM}"} \
        -DCMAKE_INSTALL_PREFIX=${CC_MQTT311_LIBS_INSTALL_DIR} -DCMAKE_BUILD_TYPE=${COMMON_BUILD_TYPE} \
        -DCMAKE_PREFIX_PATH=${COMMS_INSTALL_DIR}\;${CC_MQTT311_GENERATED_INSTALL_DIR} -DCMAKE_CXX_STANDARD=${COMMON_CXX_STANDARD} \
        ${COMMON_USE_CCACHE:+"-DCC_MQTT311_USE_CCACHE=${COMMON_USE_CCACHE}"} \
        -DCC_MQTT311_CLIENT_LIB_FORCE_PIC=ON -DCC_MQTT311_CLIENT_APPS=OFF 
    cmake --build ${CC_MQTT311_LIBS_BUILD_DIR} --config ${COMMON_BUILD_TYPE} --target install ${procs_param}
}

set -e
export VERBOSE=1
build_comms
build_cc_tools_qt
build_cc_mqtt311_generated
build_cc_mqtt311_libs
