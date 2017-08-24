cmake_minimum_required(VERSION 2.6)

project(ip_vs_ca C)

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
set(CPACK_PACKAGE_VERSION "0.1.3")
set(CPACK_PACKAGE_DESCRIPTION "get ip vs(fullnat) client addr")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${KERNEL_RELEASE}-${CPACK_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_RELOCATABLE false)
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/scripts/postinst")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/scripts/postinst")
set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_BINARY_DIR}/ChangeLog")
set(CPACK_RPM_PACKAGE_LICENSE "BSD")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Kernel")
set(CPACK_RPM_PACKAGE_DESCRIPTION ${CPACK_PACKAGE_DESCRIPTION})
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
	"/usr"
	"/lib"
	"/lib/modules"
	"/lib/modules/${KERNEL_RELEASE}"
	"/lib/modules/${KERNEL_RELEASE}/kernel"
	"/lib/modules/${KERNEL_RELEASE}/kernel/extra")
include(CPack)

add_custom_command(OUTPUT ChangeLog
	COMMAND git log --format='* %cd %aN%n- (%h) %s%d%n' --date=local | sed -r 's/[0-9]+:[0-9]+:[0-9]+ //' >> ${CMAKE_CURRENT_BINARY_DIR}/ChangeLog
	COMMENT "export git log to ChangeLog")

add_custom_target(PKGFILES ALL DEPENDS ChangeLog)

add_subdirectory(src)
