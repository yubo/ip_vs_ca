cmake_minimum_required(VERSION 3.0)

add_definitions(-g -O2 -fsigned-char -freg-struct-return -Wall -W -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Winline -Werror)


if(DEFINED ENABLE_ICMP)
	message(STATUS "DEFINED ENABLE_ICMP=${ENABLE_ICMP}")
	set(KBUILDFILE "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.icmp")
else()
	set(KBUILDFILE "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.default")
endif()


add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
	COMMAND cp -f ${KBUILDFILE} "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild"
	DEPENDS ${KBUILDFILE}
	COMMENT "Create Kbuild")

# Build the module

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko
	COMMAND make -C ${KERNEL_SRCDIR} ${CMAKE_C_FLAGS} M=${CMAKE_CURRENT_SOURCE_DIR} modules
	DEPENDS ca_core.c ca_conn.c ca_ctl.c ca_proto.c utils.c Kbuild
	COMMENT "Building ip_vs_ca.ko")

add_custom_target(KMODFILES ALL DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko)


# Installation of the module
set(module_install_path /lib/modules/${KERNEL_RELEASE}/kernel/extra/ip_vs_ca)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko
        DESTINATION ${module_install_path}
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)



