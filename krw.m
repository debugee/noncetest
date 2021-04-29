#include "krw.h"

static task_t tfp0 = MACH_PORT_NULL;
static uint64_t kslide = 0;

void setKSlide(uint64_t addr) {
    kslide = addr;
}

void setTFP0(task_t task) {
    tfp0 = task;
}

task_t getTFP0() {
    task_t tfp0 = MACH_PORT_NULL;
    pid_t pid;
    
    kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
    
    if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0))
    {
        if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
            setTFP0(tfp0);
            return tfp0;
        }
    }
    
    return MACH_PORT_NULL;
}

static bool isKBase(uint64_t kbase) {
    
    uint64_t data = kread32(kbase);
    
    if(data == MH_MAGIC_64)
        return true;
    
    return false;
}

uint64_t getKBase_via_task_info() {
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    task_dyld_info_data_t dyld_info;
    
    if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) != KERN_SUCCESS)
        return 0;
    
    uint64_t kslide = dyld_info.all_image_info_size;
    uint64_t kbase = KERNEL_IMAGE_BASE + kslide;
    
    if(!isKBase(kbase))
        return 0;
    
    setKSlide(kslide);
    
    return kbase;
}

uint64_t getKBase_via_kext() {
    // https://github.com/apple/darwin-xnu/blob/main/bsd/sys/proc_info.h#L228
    // https://opensource.apple.com/source/xnu/xnu-4570.41.2/libkern/libkern/OSKextLibPrivate.h.auto.html
    
    struct proc_regioninfo proc_info;
    char kext_name[KMOD_MAX_NAME];
    uint64_t kext_addr, kext_addr_slid;
    CFStringRef kext_name_cf;
    CFArrayRef kext_names;
    CFDictionaryRef kexts_info, kext_info;
    CFNumberRef kext_addr_cf;
    
    for(proc_info.pri_address = 0; proc_pidinfo(0, PROC_PIDREGIONINFO, proc_info.pri_address, &proc_info, PROC_PIDREGIONINFO_SIZE) == PROC_PIDREGIONINFO_SIZE; proc_info.pri_address += proc_info.pri_size)
    {
        if(proc_info.pri_protection == VM_PROT_READ && proc_info.pri_user_tag == VM_KERN_MEMORY_OSKEXT)
        {
            kern_return_t ret = kread_buf(proc_info.pri_address + LOADED_KEXT_SUMMARY_HDR_NAME_OFF, kext_name, sizeof(kext_name));
            if(ret != KERN_SUCCESS)
                return 0;

            ret = kread_buf(proc_info.pri_address + LOADED_KEXT_SUMMARY_HDR_ADDR_OFF, &kext_addr_slid, sizeof(kext_addr_slid));
            if(ret != KERN_SUCCESS)
                return 0;

            if((kext_name_cf = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, kext_name, kCFStringEncodingUTF8, kCFAllocatorNull)) == NULL)
            {
                CFRelease(kext_name_cf);
                return 0;
            }
            
            if((kext_names = CFArrayCreate(kCFAllocatorDefault, (const void **)&kext_name_cf, 1, &kCFTypeArrayCallBacks)) == NULL)
            {
                CFRelease(kext_names);
                return 0;
            }

            if((kexts_info = OSKextCopyLoadedKextInfo(kext_names, NULL)) == NULL)
            {
                CFRelease(kexts_info);
                return 0;
            }
            
            if(CFGetTypeID(kexts_info) == CFDictionaryGetTypeID() && CFDictionaryGetCount(kexts_info) != 1)
                return 0;
            
            if((kext_info = CFDictionaryGetValue(kexts_info, kext_name_cf)) == NULL)
                return 0;
            
            if(CFGetTypeID(kext_info) != CFDictionaryGetTypeID())
                return 0;
            
            if((kext_addr_cf = CFDictionaryGetValue(kext_info, CFSTR(kOSBundleLoadAddressKey))) == NULL)
                return 0;
            
            if(CFGetTypeID(kext_addr_cf) != CFNumberGetTypeID())
                return 0;
            
            if(!CFNumberGetValue(kext_addr_cf, kCFNumberSInt64Type, &kext_addr))
                return 0;
            
            if(kext_addr_slid <= kext_addr)
                return 0;
            
            uint64_t kslide = kext_addr_slid - kext_addr;
            uint64_t kbase = KERNEL_IMAGE_BASE + kslide;
            
            if(!isKBase(kbase))
                return 0;
            
            setKSlide(kslide);
            return kbase;
        }
    }
    return 0;
}

uint64_t getProc(pid_t pid) {
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/proc_internal.h#L193
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/queue.h#L470
    
    uint64_t proc = kread64(KERNPROC + kslide);
    
    while (true) {
        if(kread32(proc + PROC_P_PID_OFF) == pid) {
            return proc;
        }
        proc = kread64(proc + PROC_P_LIST_LE_PREV_OFF);
    }
    
    return 0;
}

kern_return_t kread_buf(uint64_t addr, void *buf, size_t sz) {
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_vm_size_t read_sz, out_sz = 0;

    while(sz != 0) {
        read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
            return KERN_FAILURE;
        }
        p += read_sz;
        sz -= read_sz;
        addr += read_sz;
    }
    return KERN_SUCCESS;
}

kern_return_t
kwrite_buf(uint64_t addr, const void *buf, size_t sz) {
    vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_msg_type_number_t write_sz;

    while(sz != 0) {
        write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
            return KERN_FAILURE;
        }
        p += write_sz;
        sz -= write_sz;
        addr += write_sz;
    }
    return KERN_SUCCESS;
}

uint32_t kread32(uint64_t where) {
    uint32_t out;
    kread_buf(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t kread64(uint64_t where) {
    uint64_t out;
    kread_buf(where, &out, sizeof(uint64_t));
    return out;
}

void kwrite32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    kwrite_buf(where, &_what, sizeof(uint32_t));
}

void kwrite64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    kwrite_buf(where, &_what, sizeof(uint64_t));
}
