#ifndef PATCHFINDER_H
#define PATCHFINDER_H

#include <stdint.h>
#include <string.h>


// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_kernel_pmap_nosym_11(uint32_t kbase, uint8_t* kdata, size_t ksize);

// Write 0 here.
uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 1 here.
uint32_t find_cs_enforcement_disable_amfi(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_remount_patch_offset(uint32_t region, uint8_t *kdata, size_t ksize);
void find_i_can_has_debugger_patch_off(uint32_t region,uint8_t *kdata,size_t ksize,uint32_t *found);
void find_amfi_patch_offsets(uint32_t region, uint8_t *kdata, size_t ksize, uint32_t *destination, uint32_t *target);
uint32_t find_amfi_substrate_patch(uint32_t region,uint8_t *kdata,size_t ksize);
uint32_t find_sandbox_label_update_execve(uint32_t region,uint8_t *kdata,size_t ksize);
void find_sbops(uint32_t region, uint8_t *kdata, size_t ksize, uint32_t *found);
void find_nosuid_off(uint32_t region,uint8_t *kdata,size_t ksize, uint32_t *found1,uint32_t *found2);

#endif

