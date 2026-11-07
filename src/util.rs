//! Low-level Win32 helpers shared by every check.
//!
//! Everything here is strictly read-only: registry reads, token queries and
//! effective-access checks. Nothing writes, deletes or modifies the host.

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
use windows_sys::Win32::Security::{
    AccessCheck, DuplicateToken, GetSidSubAuthority, GetSidSubAuthorityCount,
    GetTokenInformation, LookupPrivilegeNameW, MapGenericMask, GENERIC_MAPPING,
    LUID_AND_ATTRIBUTES, PRIVILEGE_SET, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, HKEY,
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// --- Access rights (defined locally to avoid pulling extra crate features) ---
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

const KEY_READ: u32 = 0x2_0019;
const SE_FILE_OBJECT: i32 = 1;
const SECURITY_IMPERSONATION: i32 = 2;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_DUPLICATE: u32 = 0x0002;
const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;

// RegGetValueW restriction flags.
const RRF_RT_REG_SZ: u32 = 0x0000_0002;
const RRF_RT_REG_EXPAND_SZ: u32 = 0x0000_0004;
const RRF_RT_REG_DWORD: u32 = 0x0000_0010;

/// Root hive selector so checks don't need to import windows-sys constants.
#[derive(Clone, Copy)]
pub enum Hive {
    Hklm,
    Hkcu,
}

impl Hive {
    fn key(self) -> HKEY {
        match self {
            Hive::Hklm => HKEY_LOCAL_MACHINE,
            Hive::Hkcu => HKEY_CURRENT_USER,
        }
    }
}

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// Read a REG_SZ / REG_EXPAND_SZ value, expanding environment strings.
pub fn reg_get_string(hive: Hive, subkey: &str, value: &str) -> Option<String> {
    let sk = to_wide(subkey);
    let vn = to_wide(value);
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
    unsafe {
        let mut cb: u32 = 0;
        let rc = RegGetValueW(
            hive.key(),
            sk.as_ptr(),
            vn.as_ptr(),
            flags,
            null_mut(),
            null_mut(),
            &mut cb,
        );
        if rc != 0 || cb == 0 {
            return None;
        }
        let mut buf = vec![0u16; (cb as usize / 2) + 1];
        let mut cb2 = (buf.len() * 2) as u32;
        let rc = RegGetValueW(
            hive.key(),
            sk.as_ptr(),
            vn.as_ptr(),
            flags,
            null_mut(),
            buf.as_mut_ptr() as *mut c_void,
            &mut cb2,
        );
        if rc != 0 {
            return None;
        }
        let s = wide_to_string(&buf);
        if s.is_empty() {
            None
        } else {
            Some(expand_path(&s))
        }
    }
}

/// Read a REG_DWORD value.
pub fn reg_get_u32(hive: Hive, subkey: &str, value: &str) -> Option<u32> {
    let sk = to_wide(subkey);
    let vn = to_wide(value);
    unsafe {
        let mut data: u32 = 0;
        let mut cb: u32 = 4;
        let rc = RegGetValueW(
            hive.key(),
            sk.as_ptr(),
            vn.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            &mut data as *mut u32 as *mut c_void,
            &mut cb,
        );
        if rc == 0 {
            Some(data)
        } else {
            None
        }
    }
}

/// Enumerate the subkey names directly under `subkey`.
pub fn reg_subkeys(hive: Hive, subkey: &str) -> Vec<String> {
    let sk = to_wide(subkey);
    let mut out = Vec::new();
    unsafe {
        let mut hk: HKEY = null_mut();
        if RegOpenKeyExW(hive.key(), sk.as_ptr(), 0, KEY_READ, &mut hk) != 0 {
            return out;
        }
        let mut idx = 0u32;
        loop {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            let rc = RegEnumKeyExW(
                hk,
                idx,
                name.as_mut_ptr(),
                &mut len,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            );
            if rc != 0 {
                break;
            }
            out.push(wide_to_string(&name[..len as usize]));
            idx += 1;
        }
        RegCloseKey(hk);
    }
    out
}

/// Enumerate the value NAMES under `subkey` (data fetched separately).
pub fn reg_value_names(hive: Hive, subkey: &str) -> Vec<String> {
    let sk = to_wide(subkey);
    let mut out = Vec::new();
    unsafe {
        let mut hk: HKEY = null_mut();
        if RegOpenKeyExW(hive.key(), sk.as_ptr(), 0, KEY_READ, &mut hk) != 0 {
            return out;
        }
        let mut idx = 0u32;
        loop {
            let mut name = [0u16; 16384];
            let mut len = name.len() as u32;
            let rc = RegEnumValueW(
                hk,
                idx,
                name.as_mut_ptr(),
                &mut len,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            );
            if rc != 0 {
                break;
            }
            out.push(wide_to_string(&name[..len as usize]));
            idx += 1;
        }
        RegCloseKey(hk);
    }
    out
}

/// Expand `%VAR%`, `\??\` and `\SystemRoot\` prefixes into a concrete path.
pub fn expand_path(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(r) = s.strip_prefix("\\??\\") {
        s = r.to_string();
    }
    let windir = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| "C:\\Windows".to_string());
    let windir = windir.trim_end_matches('\\').to_string();
    if let Some(r) = s.strip_prefix("\\SystemRoot\\") {
        s = format!("{windir}\\{r}");
    } else if let Some(r) = s.strip_prefix("System32\\").or_else(|| s.strip_prefix("system32\\")) {
        s = format!("{windir}\\System32\\{r}");
    }
    // Resolve %VAR% tokens.
    while let Some(start) = s.find('%') {
        let Some(end_rel) = s[start + 1..].find('%') else { break };
        let end = start + 1 + end_rel;
        let var = &s[start + 1..end];
        let val = std::env::var(var).unwrap_or_default();
        s = format!("{}{}{}", &s[..start], val, &s[end + 1..]);
    }
    s
}

/// Extract the executable path from a raw service / autorun command line.
pub fn parse_exe(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(expand_path(&rest[..end]));
    }
    let lower = s.to_ascii_lowercase();
    if let Some(pos) = lower.find(".exe") {
        return Some(expand_path(&s[..pos + 4]));
    }
    let first = s.split_whitespace().next()?;
    Some(expand_path(first))
}

/// For an UNQUOTED command line whose exe path contains spaces, produce the
/// intermediate paths an attacker could drop a binary at to hijack startup.
pub fn unquoted_candidates(raw: &str) -> Vec<String> {
    let s = raw.trim();
    if s.starts_with('"') {
        return Vec::new();
    }
    let lower = s.to_ascii_lowercase();
    let exe_end = match lower.find(".exe") {
        Some(p) => p + 4,
        None => return Vec::new(),
    };
    let path = &s[..exe_end];
    if !path.contains(' ') {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut prefix = String::new();
    for (i, part) in path.split(' ').enumerate() {
        if i > 0 {
            out.push(format!("{prefix}.exe"));
            prefix.push(' ');
        }
        prefix.push_str(part);
    }
    out.into_iter().map(|c| expand_path(&c)).collect()
}

/// Parent directory of a Windows path (`C:\a\b.exe` -> `C:\a`).
pub fn parent_dir(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('\\');
    trimmed.rfind('\\').map(|i| trimmed[..i].to_string())
}

pub fn file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

/// Does the CURRENT process token have effective write/modify/delete/take-owner
/// access to `path`? Uses a real `AccessCheck` against the DACL, so group
/// membership, inheritance and deny-ACEs are all honoured — not a guess.
pub fn can_write(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let wpath = to_wide(path);
    unsafe {
        let mut psd: *mut c_void = null_mut();
        let mut pdacl: *mut windows_sys::Win32::Security::ACL = null_mut();
        let rc = GetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            0x0000_0001 | 0x0000_0002 | 0x0000_0004, // OWNER | GROUP | DACL
            null_mut(),
            null_mut(),
            &mut pdacl,
            null_mut(),
            &mut psd,
        );
        if rc != 0 || psd.is_null() {
            return false;
        }

        let mut token: HANDLE = null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            LocalFree(psd);
            return false;
        }
        let mut imp: HANDLE = null_mut();
        if DuplicateToken(token, SECURITY_IMPERSONATION, &mut imp) == 0 {
            CloseHandle(token);
            LocalFree(psd);
            return false;
        }

        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        let mut desired = FILE_GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER;
        MapGenericMask(&mut desired, &mapping);

        let mut privset: PRIVILEGE_SET = std::mem::zeroed();
        let mut privlen = std::mem::size_of::<PRIVILEGE_SET>() as u32;
        let mut granted: u32 = 0;
        let mut status: i32 = 0;
        let ok = AccessCheck(
            psd,
            imp,
            desired,
            &mapping,
            &mut privset,
            &mut privlen,
            &mut granted,
            &mut status,
        );

        CloseHandle(imp);
        CloseHandle(token);
        LocalFree(psd);
        ok != 0 && status != 0
    }
}

/// The current process token privileges, as `(name, enabled)`.
pub fn token_privileges() -> Vec<(String, bool)> {
    let mut out = Vec::new();
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return out;
        }
        let mut len = 0u32;
        GetTokenInformation(token, 3 /* TokenPrivileges */, null_mut(), 0, &mut len);
        if len == 0 {
            CloseHandle(token);
            return out;
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(
            token,
            3,
            buf.as_mut_ptr() as *mut c_void,
            len,
            &mut len,
        ) == 0
        {
            CloseHandle(token);
            return out;
        }
        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let count = tp.PrivilegeCount as usize;
        let arr = tp.Privileges.as_ptr();
        for i in 0..count {
            let la: &LUID_AND_ATTRIBUTES = &*arr.add(i);
            let mut needed = 0u32;
            LookupPrivilegeNameW(null(), &la.Luid, null_mut(), &mut needed);
            if needed == 0 {
                continue;
            }
            let mut nbuf = vec![0u16; needed as usize + 1];
            let mut nlen = nbuf.len() as u32;
            if LookupPrivilegeNameW(null(), &la.Luid, nbuf.as_mut_ptr(), &mut nlen) == 0 {
                continue;
            }
            let name = wide_to_string(&nbuf);
            let enabled = la.Attributes & SE_PRIVILEGE_ENABLED != 0;
            out.push((name, enabled));
        }
        CloseHandle(token);
    }
    out
}

/// Human-readable mandatory integrity level of the current process.
pub fn integrity_level() -> String {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return "Unknown".to_string();
        }
        let mut len = 0u32;
        GetTokenInformation(token, 25 /* TokenIntegrityLevel */, null_mut(), 0, &mut len);
        if len == 0 {
            CloseHandle(token);
            return "Unknown".to_string();
        }
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, 25, buf.as_mut_ptr() as *mut c_void, len, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return "Unknown".to_string();
        }
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        if sid.is_null() {
            return "Unknown".to_string();
        }
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return "Unknown".to_string();
        }
        let rid = *GetSidSubAuthority(sid, (count - 1) as u32);
        match rid {
            0x0000..=0x0FFF => "Untrusted".to_string(),
            0x1000..=0x1FFF => "Low".to_string(),
            0x2000..=0x2FFF => "Medium".to_string(),
            0x3000..=0x3FFF => "High".to_string(),
            _ => "System".to_string(),
        }
    }
}
