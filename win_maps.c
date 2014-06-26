#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>


void show_modules() {

    unsigned char *p = NULL;
    MEMORY_BASIC_INFORMATION info;
    char buffer[MAX_PATH];

    for ( p = NULL; VirtualQuery(p, &info, sizeof(info)) == sizeof(info); p += info.RegionSize )
    {

        if (info.State != MEM_COMMIT){
            continue;
        }

        printf("%#10.10x-%#10.10x\t", info.BaseAddress, info.BaseAddress+info.RegionSize);

/*        int guard = 0, nocache = 0;

        if ( info.AllocationProtect & PAGE_NOCACHE)
            nocache = 1;
        if ( info.AllocationProtect & PAGE_GUARD )
            guard = 1;
*/
        info.AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE);

        switch (info.AllocationProtect) {
        case PAGE_READONLY:
            printf("r---");
            break;
        case PAGE_READWRITE:
            printf("rw--");
            break;
        case PAGE_WRITECOPY:
            printf("rw-p");
            break;
        case PAGE_EXECUTE:
            printf("--x-");
            break;
        case PAGE_EXECUTE_READ:
            printf("r-x-");
            break;
        case PAGE_EXECUTE_READWRITE:
            printf("rwx-");
            break;
        case PAGE_EXECUTE_WRITECOPY:
            printf("rwxp");
            break;
        case PAGE_NOACCESS:
            printf("----");
            break;
        }
        printf("\t0\t?\t0\t");

       /* if (guard)
            printf("\tguard page");
        if (nocache)
            printf("\tnon-cachable");*/

        switch (info.Type) {
        case MEM_IMAGE:
            buffer[0] = 0;
            int s = GetModuleFileNameA((HINSTANCE) info.AllocationBase, buffer, MAX_PATH);
            printf("%s", buffer);
            break;
        case MEM_MAPPED:
            printf("Mapped");
            break;
        case MEM_PRIVATE:
            printf("Private");
            break;
        default:
            printf("\t");
        }


        printf("\n");
    }
}

int main(int argc, char **argv) {

    show_modules();
    return 0;
}
