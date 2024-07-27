#ifndef _TGA_DLL_LOADER
#define _TGA_DLL_LOADER

#include "stdbool.h"
#include "string.h"
#include "stdlib.h"
#include "stdio.h"

#include "winapi/windows.h"

#include "tga/celua.h"

#define DLL_LOAD_SUCCESS 0
#define DLL_LOAD_VIRTUAL_RESERVE_FAILED 1
#define DLL_LOAD_VIRTUAL_COMMIT_FAILED 2
#define DLL_LOAD_UNSUPPORTED_RELOC_TYPE 3
#define DLL_LOAD_UNRESOLVED_IMPORTS 4
#define DLL_LOAD_VIRTUAL_PROTECT_FAILED 5
#define DLL_LOAD_ADD_FUNCTION_TABLE_FAILED 6
#define DLL_LOAD_TLS_ALLOC_FAILED 7
#define DLL_LOAD_DLLMAIN_FAILED 8


#define PE_IMAGE_NT_HEADERS(image) (IMAGE_NT_HEADERS*)((uintptr_t)(image) + ((IMAGE_DOS_HEADER*)(image))->e_lfanew)

typedef union _sym_or_ord {
    const char* sym;
    uint64_t ord; // If ord < 0x10000, it is an ordinal. sym is a ptr can't be lower than that
} sym_or_ord;

#define DLL_LOAD_IS_ORDINAL(sym_or_ord_union) ((sym_or_ord_union).ord < 0x10000)

typedef struct _manual_dll {
    uint8_t* mapped_image;
    size_t mapped_image_size;
    const char** unresolved_imports_dll;
    sym_or_ord* unresolved_imports_fun;
    size_t num_unresolved_imports;
    HINSTANCE* dependency_handles;
    size_t num_dependency_handles;
    uint32_t tls_slot;
    bool dllmain_success;
} manual_dll;

typedef uint32_t dll_load_error;

manual_dll* manual_dll_init(manual_dll* dll) {
    memset(dll, 0, sizeof(*dll));
    return dll;
}

dll_load_error dll_map_memory(const uint8_t* image, manual_dll* dll) {
    const IMAGE_NT_HEADERS* nt_headers = PE_IMAGE_NT_HEADERS(image);
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_headers);
    DWORD protect;

    dll->mapped_image = VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
    if (!dll->mapped_image) {
        return DLL_LOAD_VIRTUAL_RESERVE_FAILED;
    }
    dll->mapped_image_size = nt_headers->OptionalHeader.SizeOfImage;

    if (!VirtualAlloc(dll->mapped_image, nt_headers->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE)) {
		return DLL_LOAD_VIRTUAL_COMMIT_FAILED;
    }
    memcpy(dll->mapped_image, image, nt_headers->OptionalHeader.SizeOfHeaders);

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* section = sections + i;
        if (!VirtualAlloc(dll->mapped_image + section->VirtualAddress, section->Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE)) {
            return DLL_LOAD_VIRTUAL_COMMIT_FAILED;
        }
        memcpy(dll->mapped_image + section->VirtualAddress, image + section->PointerToRawData, section->SizeOfRawData);
    }

    return DLL_LOAD_SUCCESS;
}

dll_load_error dll_apply_relocs(manual_dll* dll) {
    const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
    const IMAGE_DATA_DIRECTORY* reloc_dd = headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC;
    const uint8_t* reloc_ptr = (void*)(dll->mapped_image + reloc_dd->VirtualAddress);
    const uint8_t* reloc_end = reloc_ptr + reloc_dd->Size;

    typedef struct _reloc {
        WORD offset: 12;
        WORD type: 4;
    } reloc;

    intptr_t difference = (intptr_t)dll->mapped_image - headers->OptionalHeader.ImageBase;

    while (reloc_ptr < reloc_end) {
        const PIMAGE_BASE_RELOCATION reloc_block = (void*)reloc_ptr;
        reloc_ptr += reloc_block->SizeOfBlock;

        for (const reloc* r = (void*)(reloc_block + 1); (char*)r < (char*)reloc_ptr; r++) {
            uint8_t* target = dll->mapped_image + reloc_block->VirtualAddress + r->offset;
            switch (r->type) {
                case IMAGE_REL_BASED_ABSOLUTE: break;
                case IMAGE_REL_BASED_HIGH:
                    *(uint16_t*)(target + 2) += (uint16_t)(difference >> 16);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(uint16_t*)target += (uint16_t)(difference & 0xFFFF);
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(uint32_t*)target += (uint32_t)difference;
                    break;
                case IMAGE_REL_BASED_HIGHADJ:
                    *(uint16_t*)(target + 2) += (uint16_t)(difference >> 16);
                    *(uint16_t*)target = *(uint16_t*)(++r);
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *(uint64_t*)target += difference;
                    break;
                default:
                    return DLL_LOAD_UNSUPPORTED_RELOC_TYPE;
            }
        }
    }

    return DLL_LOAD_SUCCESS;
}

dll_load_error dll_resolve_imports(manual_dll* dll) {
    const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
    const IMAGE_DATA_DIRECTORY* imports_dd = headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
    const IMAGE_IMPORT_DESCRIPTOR* import_dir = (void*)(dll->mapped_image + imports_dd->VirtualAddress);

    char lua_buffer[512];
    size_t num_dll_dependencies = 0;
    size_t num_imported_funcs = 0;
    for (const IMAGE_IMPORT_DESCRIPTOR* id = import_dir; id->Name != 0; id++, num_dll_dependencies++) {
        const ULONG_PTR* t = (void*)(dll->mapped_image + import_dir->OriginalFirstThunk);
        for (; *t != 0; t++, num_imported_funcs++);
    }

    dll->dependency_handles = calloc(num_dll_dependencies, sizeof(HINSTANCE));
    dll->unresolved_imports_dll = calloc(num_imported_funcs, sizeof(char*));
	dll->unresolved_imports_fun = calloc(num_imported_funcs, sizeof(sym_or_ord));

    dll_load_error error = DLL_LOAD_SUCCESS;
    for (; import_dir->Name != 0; import_dir++) {
        const char* dll_name = (void*)(dll->mapped_image + import_dir->Name);
        const bool is_ce_import = strcmpi(dll_name, "CECPP.DLL") == 0;

        const ULONG_PTR* import_ptr = (void*)(dll->mapped_image + import_dir->OriginalFirstThunk);
        ULONG_PTR* thunk_ptr = (void*)(dll->mapped_image + import_dir->FirstThunk);

        HINSTANCE dll_handle = NULL;
        if (!is_ce_import && (dll_handle = LoadLibraryA(dll_name))) {
            dll->dependency_handles[dll->num_dependency_handles++] = dll_handle;
        }

        for (; *import_ptr != 0; import_ptr++, thunk_ptr++) {
            sym_or_ord fun = {
                .sym = IMAGE_SNAP_BY_ORDINAL(*import_ptr) ?
                    (char*)(*import_ptr & 0xFFFF) :
                    (char*)(dll->mapped_image + *import_ptr + 2)
            };

            *thunk_ptr = 0;
            if (is_ce_import && !DLL_LOAD_IS_ORDINAL(fun) && !strncmp(fun.sym, "CE$", 3)) {
                snprintf(lua_buffer, sizeof(lua_buffer), "return getAddressSafe(\"%s\") or 0", fun.sym + 3);
                *thunk_ptr = CELUA_ExecuteFunctionAsync(lua_buffer, 0);
            }
            else if (!is_ce_import) {
                *thunk_ptr = (ULONG_PTR)GetProcAddress(dll_handle, fun.sym);
            }

            if (*thunk_ptr == 0) {
                error = DLL_LOAD_UNRESOLVED_IMPORTS;
                dll->unresolved_imports_dll[dll->num_unresolved_imports] = dll_name;
                dll->unresolved_imports_fun[dll->num_unresolved_imports++] = fun;
            }
        }
    }

    return error;
}

dll_load_error dll_apply_mem_protect(manual_dll* dll) {
    const IMAGE_NT_HEADERS* nt_headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_headers);
    DWORD protect;

    if (!VirtualProtect(dll->mapped_image, nt_headers->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &protect)) {
        return DLL_LOAD_VIRTUAL_PROTECT_FAILED;
    }

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* section = sections + i;

        static const DWORD prot_lookup[8] = {
            PAGE_NOACCESS,
            PAGE_EXECUTE,
            PAGE_READONLY,
            PAGE_EXECUTE_READ,
            // Starting from here, everything will have READ set even if it shouldn't
            // (we can't have a writable but not readable page)
            PAGE_READWRITE,
            PAGE_EXECUTE_READWRITE,
            PAGE_READWRITE,
            PAGE_EXECUTE_READWRITE
        };
        protect = prot_lookup[section->Characteristics >> 29];

        if (!VirtualProtect(dll->mapped_image + section->VirtualAddress, section->Misc.VirtualSize, protect, &protect)) {
            return DLL_LOAD_VIRTUAL_PROTECT_FAILED;
        }
    }

    return DLL_LOAD_SUCCESS;
}

dll_load_error dll_register_exception_table(manual_dll* dll) {
    const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
    const IMAGE_DATA_DIRECTORY* pdata_dd = headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
    if (pdata_dd->VirtualAddress == 0) {
        return DLL_LOAD_SUCCESS;
    }

    const PRUNTIME_FUNCTION fun_table = (void*)(dll->mapped_image + pdata_dd->VirtualAddress);
    return RtlAddFunctionTable(fun_table, pdata_dd->Size / sizeof(RUNTIME_FUNCTION), (uintptr_t)dll->mapped_image) ?
        DLL_LOAD_SUCCESS : DLL_LOAD_ADD_FUNCTION_TABLE_FAILED;
}

dll_load_error dll_alloc_tls_slot(manual_dll* dll) {
    const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
    const IMAGE_DATA_DIRECTORY* tls_dd = headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS;
    if (tls_dd->VirtualAddress == 0) {
        return DLL_LOAD_SUCCESS;
    }

    const IMAGE_TLS_DIRECTORY* tls_dir = (void*)(dll->mapped_image + tls_dd->VirtualAddress);

    // TlsAlloc and image TLS use the same underlying TLS array, so this should work at runtime.
    // We'll need to register this loaded_dll object with a hook on KERNEL32's entry point.
    // This will let us handle TLS memery
    dll->tls_slot = TlsAlloc();
    if (dll->tls_slot == 0) {
        return DLL_LOAD_TLS_ALLOC_FAILED;
    }

    *(DWORD*)tls_dir->AddressOfIndex = dll->tls_slot;
    return DLL_LOAD_SUCCESS;
}

/// Prepare TLS data for a new thread. This should be called in two places:
/// 1. *before* calling the mapped module's entry point for the first time, with is_process_attach = true.
/// 2. As a hook of another (NT loaded) module's DllMain, for the DLL_THREAD_ATTACH reason.
bool dll_init_tls_data(manual_dll* dll, bool is_process_attach) {
    const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
    const IMAGE_DATA_DIRECTORY* tls_dd = headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS;
    if (tls_dd->VirtualAddress == 0) {
        return true;
    }

    const IMAGE_TLS_DIRECTORY* tls_dir = (void*)(dll->mapped_image + tls_dd->VirtualAddress);

    if (TlsGetValue(dll->tls_slot) != NULL) { // TLS data already initialized!
        return false;
    }

    // Calculate TLS data sizes and align
    const size_t tls_nonzero_size = tls_dir->EndAddressOfRawData - tls_dir->StartAddressOfRawData;
    const size_t tls_total_size = tls_nonzero_size + tls_dir->SizeOfZeroFill;

    const size_t align_bits = (tls_dir->Characteristics >> 20) & 0xF;
    const size_t tls_align = align_bits ? 1 << (align_bits - 1) : 1;

    // Allocate aligned memory for TLS data
    const uintptr_t tls_unaligned = (uintptr_t)malloc(tls_total_size + tls_align + sizeof(void*));
    uint8_t* tls_aligned = (uint8_t*)((tls_unaligned + sizeof(void*) + tls_align - 1) & ~(tls_align - 1));
    ((uintptr_t*)tls_aligned)[-1] = tls_unaligned;

    // Fill in static initial data and zero pad
    memcpy(tls_aligned, (uint8_t*)tls_dir->StartAddressOfRawData, tls_nonzero_size);
    memset(tls_aligned + tls_nonzero_size, 0, tls_dir->SizeOfZeroFill);

    // Bind TLS data and call dynamic TLS callbacks for initialization
    TlsSetValue(dll->tls_slot, tls_aligned);
    for (const PIMAGE_TLS_CALLBACK* cb = (void*)tls_dir->AddressOfCallBacks; *cb != NULL; ++cb) {
        (*cb)(dll->mapped_image, is_process_attach ? DLL_PROCESS_ATTACH : DLL_THREAD_ATTACH, NULL);
    }

    return true;
}

/// Prepare TLS data for a new thread. This should be called in two places:
/// 1. When manually unloading the module, *after* calling the module's DllMain with DLL_PROCESS_DETACH.
/// 2. As a hook of another (NT loaded) module's DllMain, for *all* DETACH rasons.
bool dll_destroy_tls_data(manual_dll* dll, bool is_process_detach) {
    const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
    const IMAGE_DATA_DIRECTORY* tls_dd = headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS;
    if (tls_dd->VirtualAddress == 0) {
        return true;
    }

    const IMAGE_TLS_DIRECTORY* tls_dir = (void*)(dll->mapped_image + tls_dd->VirtualAddress);

    void** tls_aligned = TlsGetValue(dll->tls_slot);
    if (tls_aligned == NULL) { // TLS data already cleared! don't call callbacks
        return false;
    }

    for (const PIMAGE_TLS_CALLBACK* cb = (void*)tls_dir->AddressOfCallBacks; *cb != NULL; ++cb) {
        (*cb)(dll->mapped_image, is_process_detach ? DLL_PROCESS_DETACH : DLL_THREAD_DETACH, NULL);
    }

    free(tls_aligned[-1]);
    TlsSetValue(dll->tls_slot, NULL);
    return true;
}

DWORD dll_entry_stub(manual_dll* dll, DWORD reason) {
    typedef BOOL (WINAPI *dll_entry_point)(PVOID DllHandle, DWORD Reason, PVOID Reserved);

    const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
    dll_entry_point entry = (void*)(dll->mapped_image + headers->OptionalHeader.AddressOfEntryPoint);

    if (reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH) {
        dll_init_tls_data(dll, reason == DLL_PROCESS_ATTACH);
    }

    DWORD out = entry(dll->mapped_image, reason, NULL);

    if (reason == DLL_PROCESS_DETACH || reason == DLL_THREAD_DETACH) {
        dll_destroy_tls_data(dll, reason == DLL_PROCESS_DETACH);
    }

    return out;
}

dll_load_error dll_map(const uint8_t* image, manual_dll* out_dll) {
    int error = 0;
    if ((error = dll_map_memory(image, out_dll))) {
        return error;
    }
    if ((error = dll_apply_relocs(out_dll))) {
        return error;
    }
    if ((error = dll_resolve_imports(out_dll))) {
        return error;
    }
    if ((error = dll_apply_mem_protect(out_dll))) {
        return error;
    }
    if ((error = dll_alloc_tls_slot(out_dll))) {
        return error;
    }
    out_dll->dllmain_success = dll_entry_stub(out_dll, DLL_PROCESS_ATTACH) != 0;
	return out_dll->dllmain_success? DLL_LOAD_SUCCESS : DLL_LOAD_DLLMAIN_FAILED;
}

void dll_unmap(manual_dll* dll) {
    if (dll->dllmain_success) {
        dll_entry_stub(dll, DLL_PROCESS_DETACH);
    }

    if (dll->tls_slot) {
        TlsFree(dll->tls_slot);
    }
    dll->tls_slot = 0;

    for (int i = 0; i < dll->num_dependency_handles; i++) {
        FreeLibrary(dll->dependency_handles[i]);
    }
    free(dll->dependency_handles);
    dll->dependency_handles = NULL;
    dll->num_dependency_handles = 0;

    free(dll->unresolved_imports_dll);
    free(dll->unresolved_imports_fun);
    dll->unresolved_imports_dll = NULL;
    dll->unresolved_imports_fun = NULL;
    dll->num_unresolved_imports = 0;

    if (dll->mapped_image) {
        const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(dll->mapped_image);
        const IMAGE_DATA_DIRECTORY* pdata_dd = headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
        if (pdata_dd->VirtualAddress != 0) {
            const PRUNTIME_FUNCTION fun_table = (void*)(dll->mapped_image + pdata_dd->VirtualAddress);
            RtlDeleteFunctionTable(fun_table);
        }
        VirtualFree(dll->mapped_image, 0, MEM_RELEASE);
    }
    dll->mapped_image = NULL;
    dll->mapped_image_size = 0;
    dll->dllmain_success = false;
}


typedef struct _lua_map_dll_result {
    dll_load_error error;
    manual_dll dll;

    struct {
        const char* name;
        uintptr_t address;
    }* exports;
    size_t num_exports;
} lua_map_dll_result;

lua_map_dll_result* lmdr_map(const uint8_t* image) {
    lua_map_dll_result* lmdr = malloc(sizeof(lua_map_dll_result));
    memset(lmdr, 0, sizeof(*lmdr));

    lmdr->error = dll_map(image, &lmdr->dll);
    if (!lmdr->error) {
        const IMAGE_NT_HEADERS* headers = PE_IMAGE_NT_HEADERS(lmdr->dll.mapped_image);
        const IMAGE_DATA_DIRECTORY* export_dd = headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
        if (export_dd->VirtualAddress == 0) {
            return lmdr;
        }

        const IMAGE_EXPORT_DIRECTORY* exports = (void*)(lmdr->dll.mapped_image + export_dd->VirtualAddress);

        const uint32_t* funcs = (void*)(lmdr->dll.mapped_image + exports->AddressOfFunctions);
        const uint32_t* names = (void*)(lmdr->dll.mapped_image + exports->AddressOfNames);
        const uint16_t* ordinals = (void*)(lmdr->dll.mapped_image + exports->AddressOfNameOrdinals);

        lmdr->exports = calloc(exports->NumberOfNames, sizeof(*lmdr->exports));
        lmdr->num_exports = exports->NumberOfNames; // We don't publicise ordinal-only exports
        for (int i = 0; i < exports->NumberOfNames; i++) {
            lmdr->exports[i].name = (char*)lmdr->dll.mapped_image + names[i];
            lmdr->exports[i].address = (uintptr_t)lmdr->dll.mapped_image + funcs[ordinals[i]];
        }
    }

    return lmdr;
}

void lmdr_free(lua_map_dll_result* lmdr) {
    free(lmdr->exports);
    dll_unmap(&lmdr->dll);
    free(lmdr);
}

#endif