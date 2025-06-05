use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use native_tls::TlsConnector as NativeTlsConnector;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector as TokioTlsConnector;

const IP_RESOLVER: &str = "speed.cloudflare.com";
const PATH_RESOLVER: &str = "/meta";
const PROXY_FILE: &str = "Data/scan_fofa5_jun.txt"; // File input akan tetap sama, tapi kita hanya ambil IP:Port
const OUTPUT_FILE: &str = "Data/Alive/scan_fofa5_jun.txt";
const MAX_CONCURRENT: usize = 50;
const TIMEOUT_SECONDS: u64 = 5;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Memulai pemindai proxy...");

    if let Some(parent) = Path::new(OUTPUT_FILE).parent() {
        fs::create_dir_all(parent)?;
    }

    File::create(OUTPUT_FILE)?;
    println!("File {} telah dikosongkan atau dibuat sebelum proses pemindaian dimulai.", OUTPUT_FILE);

    let proxies = match read_proxy_file(PROXY_FILE) {
        Ok(proxies) => proxies,
        Err(e) => {
            eprintln!("Error membaca file proxy: {}", e);
            return Err(e.into());
        }
    };

    println!("Memuat {} proxy dari file", proxies.len());

    let original_ip_data = match check_connection(IP_RESOLVER, PATH_RESOLVER, None).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Gagal mendapatkan info IP asli: {}", e);
            return Err(e.into());
        }
    };

    let original_ip = match original_ip_data.get("clientIp") {
        Some(Value::String(ip)) => ip.clone(),
        _ => {
            eprintln!("Gagal mengekstrak IP klien asli dari respons: {:?}", original_ip_data);
            return Err("Gagal mengekstrak IP klien asli".into());
        }
    };

    println!("IP Asli: {}", original_ip);

    let active_proxies = Arc::new(Mutex::new(Vec::new()));

    let tasks = futures::stream::iter(
        proxies.into_iter().map(|proxy_line| {
            let original_ip_clone = original_ip.clone(); // Clone original_ip untuk setiap task
            let active_proxies_clone = Arc::clone(&active_proxies); // Clone Arc untuk setiap task

            async move {
                process_proxy(proxy_line, &original_ip_clone, &active_proxies_clone).await;
            }
        })
    ).buffer_unordered(MAX_CONCURRENT).collect::<Vec<()>>();

    tasks.await;

    let active_proxies_locked = active_proxies.lock().unwrap();
    if !active_proxies_locked.is_empty() {
        let mut file = File::create(OUTPUT_FILE)?;
        for proxy in active_proxies_locked.iter() {
            writeln!(file, "{}", proxy)?; // Format output sekarang hanya IP:Port
        }
        println!("Semua proxy aktif disimpan ke {}", OUTPUT_FILE);
    } else {
        println!("Tidak ditemukan proxy aktif");
    }

    println!("Pengecekan proxy selesai.");
    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut proxies = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            proxies.push(line); // Tetap baca seluruh baris, parsing akan di process_proxy
        }
    }
    Ok(proxies)
}

async fn check_connection(
    host: &str,
    path: &str,
    proxy: Option<(&str, u16)>,
) -> Result<Value> {
    let timeout_duration = Duration::from_secs(TIMEOUT_SECONDS);

    match tokio::time::timeout(timeout_duration, async {
        let payload = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240\r\n\
             Connection: close\r\n\r\n",
            path, host
        );

        let stream = if let Some((proxy_ip, proxy_port)) = proxy {
            TcpStream::connect(format!("{}:{}", proxy_ip, proxy_port)).await?
        } else {
            TcpStream::connect(format!("{}:443", host)).await?
        };

        let native_connector = NativeTlsConnector::builder().build()?;
        let tokio_connector = TokioTlsConnector::from(native_connector);
        let mut tls_stream = tokio_connector.connect(host, stream).await?;
        tls_stream.write_all(payload.as_bytes()).await?;

        let mut response = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            match tls_stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body = &response_str[body_start + 4..];
            match serde_json::from_str::<Value>(body.trim()) {
                Ok(json_data) => Ok(json_data),
                Err(e) => {
                    eprintln!("Gagal parse JSON: {}", e);
                    eprintln!("Response body untuk {}:{}: {}", host, proxy.map_or_else(|| "direct".to_string(), |(ip_val,p_val)| format!("{}:{}",ip_val,p_val)), body);
                    Err("Respons JSON tidak valid".into())
                }
            }
        } else {
            Err("Respons HTTP tidak valid: Tidak ada pemisah ditemukan".into())
        }
    }).await {
        Ok(inner_result) => inner_result,
        Err(_) => Err(Box::new(io::Error::new(io::ErrorKind::TimedOut, "Percobaan koneksi timeout")) as Box<dyn std::error::Error + Send + Sync>),
    }
}

// Modifikasi utama ada di sini
async fn process_proxy(
    proxy_line: String,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<String>>>,
) {
    // Kita asumsikan format input adalah IP,PORT[,lainnya...]
    // atau IP:PORT[,lainnya...]
    // Kita akan coba split berdasarkan ',' dulu, lalu jika tidak ada port, coba ':'
    let parts_comma: Vec<&str> = proxy_line.split(',').collect();
    
    let ip: &str;
    let port_str: &str;

    if parts_comma.len() >= 2 {
        ip = parts_comma[0].trim();
        port_str = parts_comma[1].trim();
    } else {
        // Jika split dengan koma tidak menghasilkan minimal 2 bagian, coba split dengan ':'
        // Ini berguna jika formatnya adalah IP:PORT tanpa koma di awal
        let parts_colon: Vec<&str> = proxy_line.split(':').collect();
        if parts_colon.len() >= 2 {
            ip = parts_colon[0].trim();
            port_str = parts_colon[1].trim();
            // Jika ada bagian setelah port (misal IP:PORT,country), port_str mungkin mengandung sisa string
            // Kita ambil angka saja untuk port
            if let Some(end_of_port) = port_str.find(|c: char| !c.is_digit(10)) {
                 port_str = &port_str[..end_of_port];
            }

        } else {
            println!("Format baris proxy tidak valid: {}. Diharapkan ip,port atau ip:port", proxy_line);
            return;
        }
    }
    
    // Pastikan IP tidak kosong setelah trim
    if ip.is_empty() {
        println!("Alamat IP kosong pada baris: {}", proxy_line);
        return;
    }


    let port_num = match port_str.parse::<u16>() {
        Ok(p) => p,
        Err(_) => {
            println!("Nomor port tidak valid: {} pada baris: {}", port_str, proxy_line);
            return;
        }
    };

    match check_connection(IP_RESOLVER, PATH_RESOLVER, Some((ip, port_num))).await {
        Ok(proxy_data) => {
            if let Some(Value::String(proxy_ip_val)) = proxy_data.get("clientIp") { // Ganti nama variabel
                if proxy_ip_val != original_ip {
                    // Format output sekarang hanya IP:Port
                    let proxy_entry = format!("{}:{}", ip, port_num);
                    println!("PROXY CF AKTIF!: {}", proxy_entry);

                    let mut active_proxies_locked = active_proxies.lock().unwrap();
                    active_proxies_locked.push(proxy_entry);
                } else {
                    println!("PROXY CF MATI! (IP Sama dengan asli): {}:{}", ip, port_num);
                }
            } else {
                println!("PROXY CF MATI! (Tidak ada field clientIp di respons): {}:{} - Respons: {:?}", ip, port_num, proxy_data);
            }
        },
        Err(e) => {
            println!("PROXY CF MATI! (Error koneksi): {}:{} - {}", ip, port_num, e);
        }
    }
}
