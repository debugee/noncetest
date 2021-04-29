#import <CommonCrypto/CommonDigest.h>
#include "nonce.h"
#include "krw.h"

bool setNonce(const char* generator) {
    if(!isGeneratorValid(generator)) {
        printf("Invalid generator!\n");
        return false;
    }
    
    io_service_t nvram = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    if(!nvram) {
        printf("io_service_t nvram error!\n");
        return false;
    }
    
    io_service_t apnonce = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleMobileApNonce"));
    if(!apnonce) {
        printf("io_service_t apnonce error!\n");
        return false;
    }
    
    uint64_t bootNonceSymbol = getBootNonceOSSymbol(apnonce);
    if(!bootNonceSymbol) {
        printf("Failed to get BootNonceOSSymbol!\n");
        return false;
    }
    
    uint64_t ofDict = getOfDict(nvram);
    if(!ofDict) {
        printf("getOfDict error!\n");
        return false;
    }
    
    uint64_t osString = lookupKeyInOsDict(ofDict, bootNonceSymbol);
    if(!osString) {
        printf("Failed to get os_string. Trying to generate nonce...\n");
        if(generateNonce(apnonce) != KERN_SUCCESS) {
            printf("generateNonce error!\n");
            return false;
        }
        
        osString = lookupKeyInOsDict(ofDict, bootNonceSymbol);
        if(!osString) {
            printf("lookupKeyInOsDict error!\n");
            return false;
        }
    }
    
    uint64_t stringPtr = kread64(osString + OS_STRING_STRING_OFF);
    if(!stringPtr) {
        printf("Failed to get stringPtr!\n");
        return false;
    }
    
    size_t nonceSize = 19;
    char nonceHex[nonceSize];
    
    kread_buf(stringPtr, &nonceHex, nonceSize - 1);
    printf("Current nonce: %s\n", nonceHex);
    
    kwrite_buf(stringPtr, generator, nonceSize - 1);
    
    bzero(&nonceHex, nonceSize);
    kread_buf(stringPtr, &nonceHex, nonceSize - 1);
    
    return syncNVRam(nvram);
}

bool isGeneratorValid(const char* generator) {
    char compareString[22];
    uint64_t rawGeneratorValue;
    sscanf(generator, "0x%16llx", &rawGeneratorValue);
    sprintf(compareString, "0x%016llx", rawGeneratorValue);
    if(strcmp(compareString, generator) != 0) {
        return false;
    }
    return true;
}

uint64_t findPort(mach_port_name_t port) {
    uint64_t ourTask = kread64(getProc(getpid()) + PROC_TASK);
    uint64_t itkSpace = kread64(ourTask + TASK_ITK_SPACE);
    uint64_t isTable = kread64(itkSpace + IPC_SPACE_IS_TABLE);
    
    uint32_t portIndex = port >> 8;
    const int ipcEntrySz = 0x18;
    
    uint64_t portAddr = kread64(isTable + (portIndex * ipcEntrySz));
    return portAddr;
}

uint64_t getObject(mach_port_t serv) {
    uint64_t port = findPort(serv);
    if(!port) {
        printf("failed to find port!\n");
        return 0;
    }
    return kread64(port + IPC_PORT_IP_KOBJECT);
}

uint64_t getOfDict(mach_port_t nvram_serv) {
    uint64_t nvramObj = getObject(nvram_serv);
    return kread64(nvramObj + IO_DT_NVRAM_OF_DICT_OFF);
}

uint64_t lookupKeyInOsDict(uint64_t dict, uint64_t key) {
    uint64_t value = 0x0;
    uint32_t count = kread32(dict + OS_DICTIONARY_COUNT_OFF);
    
    size_t entriessize = count * sizeof(dict_entry_t);
    void* os_dict_entries = malloc(entriessize);
    
    uint64_t entry_ptr = kread64(dict + OS_DICTIONARY_DICT_ENTRY_OFF);
    kread_buf(entry_ptr, os_dict_entries, entriessize);
    
    value = lookup_key_in_dicts(os_dict_entries, count, key);
    free(os_dict_entries);
    return value;
}

uint64_t getBootNonceOSSymbol(mach_port_t nonce_serv) {
    uint64_t nonceObj = getObject(nonce_serv);
    return kread64(nonceObj + AP_NONCE_BOOT_NONCE_OS_SYMBOL);
}

uint64_t lookup_key_in_dicts(dict_entry_t *os_dict_entries, uint32_t count, uint64_t key){
    uint64_t value = 0;
    for (int i = 0; i < count; ++i){
        if (os_dict_entries[i].key == key){
            value = os_dict_entries[i].value;
            break;
        }
    }
    return value;
}

kern_return_t generateNonce(mach_port_t nonce_serv) {
    io_connect_t nonce_conn = 0;
    kern_return_t ret = KERN_FAILURE;
    
    uint8_t nonce_d[CC_SHA384_DIGEST_LENGTH];
    size_t sz = sizeof(nonce_d);
    
    if(IOServiceOpen(nonce_serv, mach_task_self(), 0, &nonce_conn) == KERN_SUCCESS
       && nonce_conn != MACH_PORT_NULL) {
        ret = IOConnectCallStructMethod(nonce_conn, AP_NONCE_GENERATE_NONCE_SEL, NULL, 0, &nonce_d, &sz);
    }
    return ret;
}

bool syncNVRam(mach_port_t nvram_serv) {
    kern_return_t ret = IORegistryEntrySetCFProperty(nvram_serv, CFSTR("xsf1re.tempkey"), CFSTR("Hello, XsF1re!"));
    if(ret != KERN_SUCCESS) {
        return false;
    }
    
    ret = IORegistryEntrySetCFProperty(nvram_serv, CFSTR("IONVRAM-DELETE-PROPERTY"), CFSTR("xsf1re.tempkey"));
    if(ret != KERN_SUCCESS) {
        return false;
    }
    
    ret = IORegistryEntrySetCFProperty(nvram_serv, CFSTR("IONVRAM-FORCESYNCNOW-PROPERTY"), CFSTR("com.apple.System.boot-nonce"));
    if(ret != KERN_SUCCESS) {
        return false;
    }
    
    return true;
}
