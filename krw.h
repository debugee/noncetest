#include <mach/mach.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <libkern/OSKextLibPrivate.h>
#include <stdio.h>
#include <Foundation/Foundation.h>
#include <mach-o/loader.h>

#ifndef MIN
#    define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

// 6s 14.3 offset
#define KERNPROC 0xfffffff0070dc1f8

#define KERNEL_IMAGE_BASE 0xfffffff007004000
#define VM_KERN_MEMORY_OSKEXT (5)
#define LOADED_KEXT_SUMMARY_HDR_NAME_OFF (0x10)
#define LOADED_KEXT_SUMMARY_HDR_ADDR_OFF (0x60)
#define PROC_TASK (0x10)
#define PROC_P_LIST_LH_FIRST_OFF (0x0)
#define PROC_P_LIST_LE_PREV_OFF (0x8)
#define PROC_P_PID_OFF (0x68)
#define PROC_P_PID_UCRED_OFF (0xF0)
#define UCRED_CR_SVUID (0x20)
#define UCRED_CR_LABEL (0x78)
#define TASK_ITK_SPACE (0x330)
#define IPC_SPACE_IS_TABLE (0x20)
#define IPC_PORT_IP_KOBJECT (0x68)

//  Where can I find this on darwin source code?
//  https://github.com/Odyssey-Team/Odyssey/blob/master/Odyssey/post-exploit/utils/offsets.swift
#define AP_NONCE_GENERATE_NONCE_SEL (0xC8)
#define AP_NONCE_BOOT_NONCE_OS_SYMBOL (0xC0)
#define IO_DT_NVRAM_OF_DICT_OFF (0xC8)

//  https://github.com/apple/darwin-xnu/blob/xnu-7195.81.3/libkern/libkern/c++/OSDictionary.h#L119
#define OS_DICTIONARY_COUNT_OFF (0x14)
#define OS_DICTIONARY_DICT_ENTRY_OFF (0x20)

//  https://github.com/apple/darwin-xnu/blob/xnu-7195.81.3/libkern/libkern/c++/OSString.h#L120
#define OS_STRING_STRING_OFF (0x10)

//  https://github.com/apple/darwin-xnu/blob/xnu-7195.81.3/iokit/IOKit/IOUserClient.h#L503
#define IOUSERCLIENT_GET_TRAP_FOR_INDEX (0xB7)

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

CFDictionaryRef
OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);

typedef mach_port_t io_object_t;

typedef io_object_t io_service_t, io_connect_t, io_registry_entry_t;

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

kern_return_t
IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);

kern_return_t
IOServiceClose(io_connect_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

kern_return_t
IOConnectCallStructMethod(io_connect_t, uint32_t, const void *, size_t, void *, size_t *);

kern_return_t
IORegistryEntrySetCFProperty(io_registry_entry_t, CFStringRef, CFTypeRef);

extern const mach_port_t kIOMasterPortDefault;

static task_t tfp0;
task_t getTFP0();
uint64_t getKBase_via_task_info();
uint64_t getKBase_via_kext();
uint64_t getProc(pid_t pid);
kern_return_t kread_buf(uint64_t addr, void *buf, size_t sz);
kern_return_t kwrite_buf(uint64_t addr, const void *buf, size_t sz);
uint32_t kread32(uint64_t where);
uint64_t kread64(uint64_t where);
void kwrite32(uint64_t where, uint32_t what);
void kwrite64(uint64_t where, uint64_t what);
