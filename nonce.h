#include <stdio.h>
#include <Foundation/Foundation.h>

//  https://github.com/apple/darwin-xnu/blob/xnu-7195.81.3/libkern/libkern/c++/OSDictionary.h#L131
typedef struct {
    uint64_t key;
    uint64_t value;
} dict_entry_t;

bool setNonce(const char* generator);
bool isGeneratorValid(const char* generator);
uint64_t findPort(mach_port_name_t port);
uint64_t getObject(mach_port_t serv);
uint64_t getOfDict(mach_port_t nvram_serv);
uint64_t lookupKeyInOsDict(uint64_t dict, uint64_t key);
uint64_t getBootNonceOSSymbol(mach_port_t nonce_serv);
uint64_t lookup_key_in_dicts(dict_entry_t *os_dict_entries, uint32_t count, uint64_t key);
kern_return_t generateNonce(mach_port_t nonce_serv);
bool syncNVRam(mach_port_t nvram_serv);
