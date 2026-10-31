use serde::Serialize;

#[derive(Serialize)]
pub struct Connection {
    pub pid: u32,
    pub process: String,
    pub executable: Option<String>,
    pub process_note: Option<String>,
    pub family: &'static str,
    pub local: String,
    pub remote: Option<String>,
    pub state: &'static str,
    pub listening: bool,
    pub binding: Option<&'static str>,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub connections: Vec<Connection>,
    pub captured_at_ms: u64,
    pub warnings: Vec<String>,
}

#[cfg(not(windows))]
pub fn snapshot() -> Result<Snapshot, String> {
    Err("Network Monitor is currently available on Windows only.".into())
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        collections::HashMap,
        mem::{offset_of, size_of},
        net::{Ipv4Addr, Ipv6Addr, SocketAddrV6},
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
        },
        Networking::WinSock::{AF_INET, AF_INET6},
        System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };

    // Only invoked with the SDK's Copy TCP row structs (integer fields only).
    unsafe fn rows<T: Copy>(family: u32, offset: usize) -> Result<Vec<T>, String> {
        let mut bytes = 0u32;
        for _ in 0..8 {
            // u64 storage supplies adequate alignment for both Windows table types.
            let mut storage = vec![0u64; (bytes as usize).div_ceil(8).max(1)];
            let status = unsafe {
                GetExtendedTcpTable(
                    storage.as_mut_ptr().cast(),
                    &mut bytes,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if status == ERROR_INSUFFICIENT_BUFFER {
                if bytes > 64 * 1024 * 1024 {
                    return Err("TCP table exceeded the size limit.".into());
                }
                continue;
            }
            if status != NO_ERROR {
                return Err(format!("Windows TCP table error {status}"));
            }
            let available = storage.len() * 8;
            let count = storage[0] as u32 as usize;
            let required = count
                .checked_mul(size_of::<T>())
                .and_then(|n| n.checked_add(offset))
                .ok_or("Invalid TCP table size")?;
            if required > available || required > bytes as usize {
                return Err("Incomplete Windows TCP table.".into());
            }
            let pointer = unsafe { storage.as_ptr().cast::<u8>().add(offset) };
            return Ok((0..count)
                .map(|i| unsafe {
                    std::ptr::read_unaligned(pointer.add(i * size_of::<T>()).cast::<T>())
                })
                .collect());
        }
        Err("TCP table changed repeatedly; try refreshing again.".into())
    }

    fn process(pid: u32) -> (String, Option<String>, Option<String>) {
        if pid == 0 || pid == 4 {
            return (
                if pid == 4 {
                    "System"
                } else {
                    "System / unowned"
                }
                .into(),
                None,
                Some("No user executable available for this system entry.".into()),
            );
        }
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return (
                format!("PID {pid}"),
                None,
                Some("Process exited or access to its executable is restricted.".into()),
            );
        }
        let mut path = vec![0u16; 32768];
        let mut length = path.len() as u32;
        let success =
            unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) };
        unsafe {
            CloseHandle(handle);
        }
        if success == 0 {
            return (
                format!("PID {pid}"),
                None,
                Some("Executable path could not be read; process may have exited.".into()),
            );
        }
        let path = String::from_utf16_lossy(&path[..length as usize]);
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("PID {pid}"));
        (name, Some(path), None)
    }

    fn state(value: u32) -> &'static str {
        match value {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RECEIVED",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT_1",
            7 => "FIN_WAIT_2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "UNKNOWN",
        }
    }
    fn port(value: u32) -> u16 {
        u16::from_be(value as u16)
    }
    fn binding(loopback: bool, unspecified: bool, listening: bool) -> Option<&'static str> {
        listening.then_some(if loopback {
            "Localhost"
        } else if unspecified {
            "All interfaces"
        } else {
            "Specific interface"
        })
    }

    pub fn snapshot() -> Result<Snapshot, String> {
        // SAFETY: each address family and offset matches the SDK row type,
        // whose fields are integers or byte arrays with no invalid bit patterns.
        let ipv4 = unsafe {
            rows::<MIB_TCPROW_OWNER_PID>(AF_INET as u32, offset_of!(MIB_TCPTABLE_OWNER_PID, table))
        };
        let ipv6 = unsafe {
            rows::<MIB_TCP6ROW_OWNER_PID>(
                AF_INET6 as u32,
                offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
            )
        };
        if ipv4.is_err() && ipv6.is_err() {
            return Err(format!(
                "IPv4: {}; IPv6: {}",
                ipv4.err().unwrap(),
                ipv6.err().unwrap()
            ));
        }
        let mut result = Snapshot {
            connections: vec![],
            captured_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            warnings: vec![],
        };
        let mut processes = HashMap::new();
        match ipv4 {
            Err(e) => result.warnings.push(format!("IPv4: {e}")),
            Ok(rows) => {
                for row in rows {
                    let local = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                    let remote = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
                    let (name, executable, note) = processes
                        .entry(row.dwOwningPid)
                        .or_insert_with(|| process(row.dwOwningPid));
                    result.connections.push(Connection {
                        pid: row.dwOwningPid,
                        process: name.clone(),
                        executable: executable.clone(),
                        process_note: note.clone(),
                        family: "IPv4",
                        local: format!("{local}:{}", port(row.dwLocalPort)),
                        remote: (row.dwState != 2)
                            .then(|| format!("{remote}:{}", port(row.dwRemotePort))),
                        state: state(row.dwState),
                        listening: row.dwState == 2,
                        binding: binding(
                            local.is_loopback(),
                            local.is_unspecified(),
                            row.dwState == 2,
                        ),
                    });
                }
            }
        }
        match ipv6 {
            Err(e) => result.warnings.push(format!("IPv6: {e}")),
            Ok(rows) => {
                for row in rows {
                    let local = Ipv6Addr::from(row.ucLocalAddr);
                    let remote = Ipv6Addr::from(row.ucRemoteAddr);
                    let (name, executable, note) = processes
                        .entry(row.dwOwningPid)
                        .or_insert_with(|| process(row.dwOwningPid));
                    result.connections.push(Connection {
                        pid: row.dwOwningPid,
                        process: name.clone(),
                        executable: executable.clone(),
                        process_note: note.clone(),
                        family: "IPv6",
                        local: SocketAddrV6::new(
                            local,
                            port(row.dwLocalPort),
                            0,
                            row.dwLocalScopeId,
                        )
                        .to_string(),
                        remote: (row.dwState != 2).then(|| {
                            SocketAddrV6::new(
                                remote,
                                port(row.dwRemotePort),
                                0,
                                row.dwRemoteScopeId,
                            )
                            .to_string()
                        }),
                        state: state(row.dwState),
                        listening: row.dwState == 2,
                        binding: binding(
                            local.is_loopback(),
                            local.is_unspecified(),
                            row.dwState == 2,
                        ),
                    });
                }
            }
        }
        result.connections.sort_by(|a, b| {
            (a.pid, &a.family, &a.local, &a.remote).cmp(&(b.pid, &b.family, &b.local, &b.remote))
        });
        Ok(result)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn captures_real_local_listener_and_connection_with_process_path() {
            use std::net::{TcpListener, TcpStream};
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let _client = TcpStream::connect(address).unwrap();
            let (_server, _) = listener.accept().unwrap();
            let snapshot = snapshot().unwrap();
            let row = snapshot
                .connections
                .iter()
                .find(|c| {
                    c.listening && c.local == address.to_string() && c.pid == std::process::id()
                })
                .expect("listener missing");
            assert_eq!(row.binding, Some("Localhost"));
            assert!(row.executable.is_some());
            assert!(snapshot
                .connections
                .iter()
                .any(|c| c.pid == std::process::id()
                    && c.state == "ESTABLISHED"
                    && c.remote.as_deref() == Some(&address.to_string())));
            assert_eq!(port(u16::to_be(443) as u32), 443);
        }
    }
}

#[cfg(windows)]
pub use platform::snapshot;
