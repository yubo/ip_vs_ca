cmake_minimum_required(VERSION 3.0)

ADD_DEFINITIONS(-g -O2 -fsigned-char -freg-struct-return -Wall -W -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Winline -Werror)

# Build the module

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko
	COMMAND make -C ${KERNEL_SRCDIR} M=${CMAKE_CURRENT_SOURCE_DIR}
	DEPENDS ca_core.c ca_conn.c ca_ctl.c ca_proto.c utils.c
	COMMENT "Building ip_vs_ca.ko")

ADD_CUSTOM_TARGET(KMODFILES ALL DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko)


# Installation of the module
SET(module_install_path /lib/modules/${KERNEL_RELEASE}/kernel/extra/ip_vs_ca)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko
        DESTINATION ${module_install_path}
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)



