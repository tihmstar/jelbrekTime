//
//  offsetfinder.h
//  v0rtex
//
//  Created by tihmstar on 20.12.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#ifndef offsetfinder_h
#define offsetfinder_h

#include <stdint.h>

typedef struct{
    uint32_t offset_zone_map;
    uint32_t offset_kernel_map;
    uint32_t offset_kernel_task;
    uint32_t offset_realhost;
    uint32_t offset_bzero;
    uint32_t offset_bcopy;
    uint32_t offset_copyin;
    uint32_t offset_copyout;
    uint32_t offset_ipc_port_alloc_special;
    uint32_t offset_ipc_kobject_set;
    uint32_t offset_ipc_port_make_send;
    uint32_t offset_rop_ldr_r0_r0_0xc;
    uint32_t offset_chgproccnt;
    uint32_t offset_kauth_cred_ref;
    uint32_t offset_OSSerializer_serialize;
    uint32_t offset_ipc_space_is_task;
    uint32_t offset_task_itk_self;
    uint32_t offset_task_itk_registered;
    uint32_t offset_vtab_get_external_trap_for_index;
    uint32_t offset_iouserclient_ipc;
    uint32_t offset_proc_ucred;
    uint32_t offset_task_bsd_info;
    uint32_t offset_sizeof_task;
}t_offsets;

extern t_offsets *guoffsets;

// Initializer
t_offsets *info_to_target_environment(char *uname);

#endif /* offsetfinder_h */
