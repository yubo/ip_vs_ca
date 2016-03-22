cmake_minimum_required(VERSION 2.6)

PROJECT(ip_vs_ca C)

execute_process(COMMAND uname -r
	OUTPUT_VARIABLE KERNEL_RELEASE
	OUTPUT_STRIP_TRAILING_WHITESPACE)

find_path(KERNEL_SRCDIR Makefile PATHS
	/lib/modules/${KERNEL_RELEASE}/source
	/lib/modules/${KERNEL_RELEASE}/build)

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel source: ${KERNEL_SRCDIR}")

set(CPACK_GENERATOR "RPM;DEB")
set(CPACK_PACKAGE_NAME "ip_vs_ca")
set(CPACK_PACKAGE_CONTACT "yubo@yubo.org")
set(CPACK_PACKAGE_VENDOR "yubo.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ip vs ca - get ip vs(fullnat) client addr")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_PACKAGE_DESCRIPTION "get ip vs(fullnat) client addr")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${KERNEL_RELEASE}-${CPACK_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_BINARY_DIR}/ChangeLog")
set(CPACK_PACKAGE_RELOCATABLE "")
include(CPack)


ADD_CUSTOM_COMMAND(OUTPUT ChangeLog
	COMMAND git log --format='* %cd %aN%n- (%h) %s%d%n' --date=local | sed -r 's/[0-9]+:[0-9]+:[0-9]+ //' >> ${CMAKE_CURRENT_BINARY_DIR}/ChangeLog
	COMMENT "export git log to ChangeLog")

ADD_CUSTOM_TARGET(PKGFILES ALL DEPENDS ChangeLog)

add_subdirectory(src)
