#include <errno.h>
#include <string.h>             // strcmp, strerror
#include <sys/utsname.h>        // uname
#import <Foundation/Foundation.h>

#include "common.h"             // LOG, kptr_t
#include "offsets.h"

static offsets_t *offsets[] =
{
    &(offsets_t){
        .version = "Darwin Kernel Version 17.2.0: Fri Sep 29 18:03:18 PDT 2017; root:xnu-4570.20.62~2/RELEASE_ARM_T8004",
        .base                               = 0x80001000,
        .sizeof_task                        = 0x3b0,
        .task_itk_self                      = 0x9c,
        .task_itk_registered                = 0x1dc,
        .task_bsd_info                      = 0x22c,
        .proc_ucred                         = 0x98,
        .ipc_space_is_task                  = 0x18,
        .realhost_special                   = 0x8,
        .iouserclient_ipc                   = 0x5c,
        .vtab_get_retain_count              = 0x3,
        .vtab_get_external_trap_for_index   = 0xe1,
        .zone_map                           = 0x804188e0,
        .kernel_map                         = 0x80456034,
        .kernel_task                        = 0x80456030,
        .realhost                           = 0x80404150,
        .copyin                             = 0x80007b9c,
        .copyout                            = 0x80007c74,
        .chgproccnt                         = 0x8027cc17,
        .kauth_cred_ref                     = 0x8025e78b,
        .ipc_port_alloc_special             = 0x80019035,
        .ipc_kobject_set                    = 0x800290b7,
        .ipc_port_make_send                 = 0x80018c55,
        .osserializer_serialize             = 0x8030687d,
        .rop_ldr_r0_r0_0xc                  = 0x802d1d45,
    },
    NULL,
};

offsets_t* get_offsets(void)
{
    struct utsname u;
    if(uname(&u) != 0)
    {
        LOG("uname: %s", strerror(errno));
        return 0;
    }

    // TODO: load from file

    for(size_t i = 0; offsets[i] != 0; ++i)
    {
        if(strcmp(u.version, offsets[i]->version) == 0)
        {
            return offsets[i];
        }
    }

    LOG("Failed to get offsets for kernel version: %s", u.version);
    return NULL;
}
