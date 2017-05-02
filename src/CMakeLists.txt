cmake_minimum_required(VERSION 3.0)

if(NOT DEFINED DISABLE_ICMP)
	message(STATUS "ENABLE ICMP")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DIP_VS_CA_ICMP")
endif()

if(DEFINED ENABLE_DEBUG)
	message(STATUS "ENABLE_DEBUG: ${ENABLE_DEBUG}")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DIP_VS_CA_DEBUG")
endif()

file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.ccflags"
	"\nccflags-y := ${CMAKE_C_FLAGS}\n" )

add_custom_target(KMODFILES ALL
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko)

add_custom_command(OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild"
	COMMAND cat 
		"${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.default"
		"${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.ccflags" 
		> "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild"
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.ccflags"
		"${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.default"
	COMMENT "Create Kbuild")

# Build the module
add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko
	COMMAND make -C ${KERNEL_SRCDIR} M=${CMAKE_CURRENT_SOURCE_DIR} modules
	DEPENDS ca_core.c ca_conn.c ca_ctl.c ca_proto.c utils.c Kbuild
	COMMENT "Building ip_vs_ca.ko")


# Installation of the module
set(module_install_path /lib/modules/${KERNEL_RELEASE}/kernel/extra/ip_vs_ca)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/ip_vs_ca.ko
        DESTINATION ${module_install_path}
        PERMISSIONS OWNER_READ OWNER_EXECUTE
			GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)




