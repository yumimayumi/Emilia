use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write}; // Read dihapus karena AsyncReadExt akan digunakan
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use native_tls::TlsConnector as NativeTlsConnector; // Renamed to avoid conflict
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Untuk read_exact, write_all async
use tokio::net::TcpStream; // TcpStream async dari Tokio
use tokio_native_tls::TlsConnector as TokioTlsConnector; // Konektor TLS async

const IP_RESOLVER: &str = "speed.cloudflare.com";
const PATH_RESOLVER: &str = "/meta";
const PROXY_FILE: &str = "Data/ProxyIsp.txt";
const OUTPUT_FILE: &str = "Data/alive.txt";
const MAX_CONCURRENT: usize = 100;
const TIMEOUT_SECONDS: u64 = 3;

// Define a custom error type that implements Send + Sync
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting proxy scanner...");

    // Create output directory if it doesn't exist
    if let Some(parent) = Path::new(OUTPUT_FILE).parent() {
        fs::create_dir_all(parent)?;
    }

    // Clear output file before starting
    // File::create akan mengosongkan file jika sudah ada atau membuatnya jika belum
    File::create(OUTPUT_FILE)?;
    println!("File {} has been cleared or created before scanning process started.", OUTPUT_FILE);

    // Read proxy list from file
    let proxies = match read_proxy_file(PROXY_FILE) {
        Ok(proxies) => proxies,
        Err(e) => {
            eprintln!("Error reading proxy file: {}", e);
            return Err(e.into());
        }
    };

    println!("Loaded {} proxies from file", proxies.len());

    // Get original IP (without proxy)
    let original_ip_data = match check_connection(IP_RESOLVER, PATH_RESOLVER, None).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to get original IP info: {}", e);
            // Consider if you want to exit here. If speed.cloudflare.com is down, no checks can be done.
            return Err(e.into());
        }
    };

    let original_ip = match original_ip_data.get("clientIp") {
        Some(Value::String(ip)) => ip.clone(),
        _ => {
            eprintln!("Failed to extract original client IP from response: {:?}", original_ip_data);
            return Err("Failed to extract original client IP".into());
        }
    };

    println!("Original IP: {}", original_ip);

    // Store active proxies
    let active_proxies = Arc::new(Mutex::new(Vec::new()));

    // Process proxies concurrently
    let tasks = futures::stream::iter(
        proxies.into_iter().map(|proxy_line| {
            let original_ip = original_ip.clone();
            let active_proxies = Arc::clone(&active_proxies);

            // tokio::spawn akan menjalankan setiap future process_proxy secara independen
            // Ini adalah cara yang lebih idiomatik untuk menjalankan banyak tugas async di Tokio
            // daripada hanya mengandalkan buffer_unordered pada stream dari async blok.
            // Namun, karena buffer_unordered sudah menangani konkurensi,
            // tokio::spawn di sini mungkin redundan jika process_proxy itu sendiri tidak
            // melakukan spawn lebih lanjut atau operasi berat CPU yang panjang.
            // Untuk I/O bound seperti ini, buffer_unordered sudah cukup.
            // Mari kita tetap dengan struktur asli untuk kesederhanaan, karena buffer_unordered sudah menangani konkurensi.
            async move {
                process_proxy(proxy_line, &original_ip, &active_proxies).await;
            }
        })
    ).buffer_unordered(MAX_CONCURRENT).collect::<Vec<()>>();

    tasks.await;

    // Save active proxies to file
    let active_proxies_locked = active_proxies.lock().unwrap(); // Renamed for clarity
    if !active_proxies_locked.is_empty() {
        let mut file = File::create(OUTPUT_FILE)?; // Buka lagi untuk menulis, ini akan menimpa
        for proxy in active_proxies_locked.iter() {
            writeln!(file, "{}", proxy)?;
        }
        println!("All active proxies saved to {}", OUTPUT_FILE);
    } else {
        println!("No active proxies found");
    }

    println!("Proxy checking completed.");
    Ok(())
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut proxies = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            proxies.push(line);
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

    // Bungkus seluruh operasi koneksi dalam tokio::time::timeout
    match tokio::time::timeout(timeout_duration, async {
        // Build HTTP request payload
        let payload = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240\r\n\
             Connection: close\r\n\r\n",
            path, host
        );

        // Create TCP connection
        let stream = if let Some((proxy_ip, proxy_port)) = proxy {
            // Connect to proxy
            TcpStream::connect(format!("{}:{}", proxy_ip, proxy_port)).await?
        } else {
            // Connect directly to host (Tokio's connect can resolve hostnames)
            TcpStream::connect(format!("{}:443", host)).await?
        };

        // Create TLS connection
        // NativeTlsConnector dikonfigurasi terlebih dahulu
        let native_connector = NativeTlsConnector::builder().build()?;
        // Kemudian dibungkus dengan TokioTlsConnector untuk penggunaan async
        let tokio_connector = TokioTlsConnector::from(native_connector);

        let mut tls_stream = tokio_connector.connect(host, stream).await?;

        // Send HTTP request
        tls_stream.write_all(payload.as_bytes()).await?;

        // Read response
        let mut response = Vec::new();
        // Menggunakan buffer yang sama ukurannya
        let mut buffer = [0; 4096];

        // Loop untuk membaca data dari stream
        // AsyncReadExt::read akan mengembalikan Ok(0) saat EOF.
        loop {
            match tls_stream.read(&mut buffer).await {
                Ok(0) => break, // End of stream
                Ok(n) => response.extend_from_slice(&buffer[..n]),
                Err(e) => {
                    // Jika jenis error adalah WouldBlock, dalam konteks async,
                    // ini biasanya ditangani oleh runtime (tidak akan sampai ke sini jika .await digunakan dengan benar).
                    // Namun, jika ada error I/O lain, kita return.
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                }
            }
        }

        // Parse response
        let response_str = String::from_utf8_lossy(&response);

        // Split headers and body
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body = &response_str[body_start + 4..];

            // Try to parse the JSON body
            match serde_json::from_str::<Value>(body.trim()) {
                Ok(json_data) => Ok(json_data),
                Err(e) => {
                    eprintln!("Failed to parse JSON: {}", e);
                    eprintln!("Response body for {}:{}: {}", host, proxy.map_or_else(|| "direct".to_string(), |(ip,p)| format!("{}:{}",ip,p)), body);
                    Err("Invalid JSON response".into())
                }
            }
        } else {
            Err("Invalid HTTP response: No separator found".into())
        }
    }).await {
        Ok(inner_result) => inner_result, // Hasil dari blok async (bisa Ok atau Err)
        Err(_) => Err(Box::new(io::Error::new(io::ErrorKind::TimedOut, "Connection attempt timed out")) as Box<dyn std::error::Error + Send + Sync>), // Error karena timeout
    }
}


fn clean_org_name(org_name: &str) -> String {
    org_name.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect()
}

async fn process_proxy(
    proxy_line: String,
    original_ip: &str,
    active_proxies: &Arc<Mutex<Vec<String>>>,
) {
    let parts: Vec<&str> = proxy_line.split(',').collect();
    if parts.len() < 4 {
        println!("Invalid proxy line format: {}. Expected ip,port,country,org", proxy_line);
        return;
    }

    let ip = parts[0];
    let port_str = parts[1]; // Renamed to avoid conflict with port_num
    let country = parts[2];
    let org = parts[3];

    let port_num = match port_str.parse::<u16>() {
        Ok(p) => p,
        Err(_) => {
            println!("Invalid port number: {} in line: {}", port_str, proxy_line);
            return;
        }
    };

    match check_connection(IP_RESOLVER, PATH_RESOLVER, Some((ip, port_num))).await {
        Ok(proxy_data) => {
            if let Some(Value::String(proxy_ip)) = proxy_data.get("clientIp") {
                if proxy_ip != original_ip {
                    let org_name_from_response = if let Some(Value::String(org_val)) = proxy_data.get("asOrganization") {
                        clean_org_name(org_val)
                    } else {
                        // Gunakan org dari file jika tidak ada di response, setelah dibersihkan
                        clean_org_name(org)
                    };

                    let proxy_entry = format!("{},{},{},{}", ip, port_num, country, org_name_from_response);
                    println!("CF PROXY LIVE!: {}", proxy_entry);

                    let mut active_proxies_locked = active_proxies.lock().unwrap();
                    active_proxies_locked.push(proxy_entry);
                } else {
                    println!("CF PROXY DEAD! (Same IP as original): {}:{}", ip, port_num);
                }
            } else {
                println!("CF PROXY DEAD! (No clientIp field in response): {}:{} - Response: {:?}", ip, port_num, proxy_data);
            }
        },
        Err(e) => {
            println!("CF PROXY DEAD! (Error connecting): {}:{} - {}", ip, port_num, e);
        }
    }
}
