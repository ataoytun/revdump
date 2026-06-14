use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

/// Resolve an ntdll export to its absolute address. ntdll is mapped at the same base in every
/// process this boot (it's a known-DLL), so an address resolved in our own process is valid in
/// the target — which lets us breakpoint ntdll functions without reading the target's exports.
pub fn ntdll_export(name: &str) -> Option<usize> {
    let module_name: Vec<u16> = "ntdll.dll"
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    let mut export_name: Vec<u8> = name.bytes().collect();
    export_name.push(0);
    // SAFETY: ntdll is always loaded; both names are NUL-terminated.
    unsafe {
        let module = GetModuleHandleW(module_name.as_ptr());
        if module.is_null() {
            return None;
        }
        GetProcAddress(module, export_name.as_ptr()).map(|f| f as usize)
    }
}
