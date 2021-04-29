#include <stdio.h>
#include <Foundation/Foundation.h>
#include "krw.h"
#include "nonce.h"

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
        //  Stage 1 - Get Kernel R/W Privileges;
        tfp0 = getTFP0();
        if(tfp0 == MACH_PORT_NULL)
        {
            printf("Failed to get tfp0\n");
            return -1;
        }
        printf("tfp0: 0x%x\n", tfp0);
        
        //  Stage 2 - get kernel base and kernel slide;
        uint64_t kbase = getKBase_via_kext();
        printf("kernel base (kext): 0x%llx\n", kbase);
        uint64_t kbase2 = getKBase_via_task_info();
        printf("kernel base (task_info): 0x%llx\n", kbase2);
        
        //  Stage 3 - set generator
        if(!setNonce("0x1111111111111111")) {
            printf("Failed to set generator!\n");
        }
        printf("Successfully set generator.\n");
        
        mach_port_deallocate(mach_task_self(), tfp0);
        
		return 0;
	}
}
