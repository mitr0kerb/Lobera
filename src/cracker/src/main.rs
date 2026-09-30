// lobera-crack — cracker offline de hashes Kerberos y NTLM
// Autor: mitr0kerb
//
// Formatos soportados:
//   AS-REP    ($krb5asrep$23$...)         — ASREPRoasting (RC4-HMAC)
//   TGS-REP   ($krb5tgs$23$*...*$...$...)  — Kerberoasting (RC4-HMAC)
//   NTLM      (32 hex chars)               — NT hashes
//   NetNTLMv2 ($NETNTLMv2$...)             — capturas de Responder
//
// Uso:
//   lobera-crack -f asrep  -H '$krb5asrep$23$...' -w rockyou.txt
//   lobera-crack -f tgs    -H '$krb5tgs$23$*...'  -w rockyou.txt
//   lobera-crack -f ntlm   -H aad3b435...          -w rockyou.txt
//   lobera-crack -f ntlmv2 -H '$NETNTLMv2$...'    -w rockyou.txt
//   lobera-crack -f tgs    -H hashes.txt           -w rockyou.txt
//   lobera-crack -f auto   -H hashes.txt           -w rockyou.txt
//
// Output JSON a stdout; progreso/errores a stderr.

use clap::Parser;
use md4::{Digest as _, Md4};
use rayon::prelude::*;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;


// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "lobera-crack", about = "Cracker offline de hashes Kerberos y NTLM")]
struct Args {
    /// Tipo de hash: asrep | tgs | ntlm | ntlmv2 | auto
    #[arg(short = 'f', long = "format", default_value = "auto")]
    format: String,

    /// Hash a crackear, o ruta a fichero con uno por línea
    #[arg(short = 'H', long = "hash")]
    hash: String,

    /// Wordlist (un password por línea)
    #[arg(short = 'w', long = "wordlist")]
    wordlist: String,

    /// Threads (0 = todos los cores disponibles)
    #[arg(short = 't', long = "threads", default_value = "0")]
    threads: usize,

    /// Mostrar progreso cada N palabras (0 = desactivado)
    #[arg(long = "progress", default_value = "100000")]
    progress: u64,

    /// Solo output JSON (sin mensajes de progreso en stderr)
    #[arg(long = "json-only")]
    json_only: bool,
}

// ── Output ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct CrackedEntry {
    hash:      String,
    password:  String,
    #[serde(rename = "type")]
    hash_type: String,
}

#[derive(Serialize)]
struct Output {
    cracked: Vec<CrackedEntry>,
    total:   u64,
    found:   u64,
    elapsed: String,
}

// ── Tipos de hash ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
enum HashType {
    Asrep(KrbHash),
    Tgs(KrbHash),
    Ntlm(String),
    NtlmV2(NtlmV2Hash),
}

#[derive(Clone, Debug)]
struct KrbHash {
    raw:      String,
    checksum: Vec<u8>, // 16 bytes
    data:     Vec<u8>, // resto
}

#[derive(Clone, Debug)]
struct NtlmV2Hash {
    raw:         String,
    user:        String,
    domain:      String,
    server_chal: Vec<u8>,
    blob:        Vec<u8>,
    response:    Vec<u8>,
}

// ── Parseo ────────────────────────────────────────────────────────────────────

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

fn parse_hash_auto(raw: &str) -> Option<HashType> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return None;
    }
    if raw.starts_with("$krb5asrep$") {
        return parse_asrep(raw);
    }
    if raw.starts_with("$krb5tgs$") {
        return parse_tgs(raw);
    }
    if raw.starts_with("$NETNTLMv2$") || raw.starts_with("$NETNTLM$") {
        return parse_ntlmv2(raw);
    }
    if raw.len() == 32 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(HashType::Ntlm(raw.to_lowercase()));
    }
    None
}

fn parse_asrep(raw: &str) -> Option<HashType> {
    // $krb5asrep$23$user@DOMAIN:CHECKSUM_HEX$DATA_HEX
    let colon = raw.find(':')?;
    let after  = &raw[colon + 1..];
    let dollar = after.find('$')?;
    Some(HashType::Asrep(KrbHash {
        raw:      raw.to_string(),
        checksum: decode_hex(&after[..dollar])?,
        data:     decode_hex(&after[dollar + 1..])?,
    }))
}

fn parse_tgs(raw: &str) -> Option<HashType> {
    // $krb5tgs$23$*user$DOMAIN$spn*$CHECKSUM$DATA
    // Los últimos dos segmentos separados por $ son checksum y data
    let last   = raw.rfind('$')?;
    let data   = decode_hex(&raw[last + 1..])?;
    let second = raw[..last].rfind('$')?;
    let cksum  = decode_hex(&raw[second + 1..last])?;
    Some(HashType::Tgs(KrbHash {
        raw: raw.to_string(),
        checksum: cksum,
        data,
    }))
}

fn parse_ntlmv2(raw: &str) -> Option<HashType> {
    // $NETNTLMv2$USER::DOMAIN$SERVER_CHAL$RESPONSE$BLOB
    // Formato exacto de Responder/hashcat mode 5600
    let stripped = raw.trim_start_matches("$NETNTLMv2$")
                      .trim_start_matches("$NETNTLM$");
    let parts: Vec<&str> = stripped.splitn(5, '$').collect();
    if parts.len() < 5 {
        return None;
    }
    // parts[0] = USER::DOMAIN, [1]=server_chal, [2]=response, [3]=blob, [4]=...
    // En hashcat 5600: USER::DOMAIN:server_chal:NTProofStr:blob
    // Reajustamos por si viene en formato alternativo
    let user_domain: Vec<&str> = parts[0].splitn(3, ':').collect();
    let (user, domain) = if user_domain.len() >= 2 {
        (user_domain[0].to_string(), user_domain[1].to_string())
    } else {
        (parts[0].to_string(), String::new())
    };

    Some(HashType::NtlmV2(NtlmV2Hash {
        raw:         raw.to_string(),
        user,
        domain,
        server_chal: decode_hex(parts[1])?,
        response:    decode_hex(parts[2])?,
        blob:        decode_hex(parts[3])?,
    }))
}

fn force_parse(raw: &str, fmt: &str) -> Option<HashType> {
    match fmt {
        "asrep"  => parse_asrep(raw),
        "tgs"    => parse_tgs(raw),
        "ntlmv2" => parse_ntlmv2(raw),
        "ntlm"   => {
            let s = raw.trim();
            if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(HashType::Ntlm(s.to_lowercase()))
            } else {
                None
            }
        }
        _ => parse_hash_auto(raw),
    }
}

// ── Primitivas criptográficas ─────────────────────────────────────────────────

/// NT hash: MD4(UTF-16LE(password))
fn nt_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut h = Md4::new();
    h.update(&utf16);
    h.finalize().into()
}

/// Pure-Rust MD5 (RFC 1321)
fn md5_hash(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    ];
    let mut msg = data.to_vec();
    let orig_len_bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 { m[i] = u32::from_le_bytes(chunk[i*4..i*4+4].try_into().unwrap()); }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64usize {
            let (f, g) = match i {
                0..=15  => (b & c | !b & d, i),
                16..=31 => (d & b | !d & c, (5*i+1)%16),
                32..=47 => (b ^ c ^ d, (3*i+5)%16),
                _       => (c ^ (b | !d), (7*i)%16),
            };
            let temp = d; d = c; c = b;
            b = b.wrapping_add(a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]).rotate_left(S[i]));
            a = temp;
        }
        a0 = a0.wrapping_add(a); b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c); d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    // HMAC-MD5: ipad/opad construction
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hk = md5_hash(key);
        k[..16].copy_from_slice(&hk);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(data);
    let inner_hash = md5_hash(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash);
    md5_hash(&outer)
}

/// RC4 (arc4) implementado en puro Rust — sin dependencias externas
fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut out = data.to_vec();
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    for byte in out.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        *byte ^= s[i.wrapping_add(s[j as usize]) as usize];
    }
    out
}

// ── Verificadores ─────────────────────────────────────────────────────────────

/// RC4-HMAC para AS-REP (hashcat mode 18200) y TGS-REP (hashcat mode 13100)
/// K1 = HMAC-MD5(NT, usage_constant)
/// K3 = HMAC-MD5(K1, checksum)
/// plaintext = RC4(K3, data)
/// verify = HMAC-MD5(K1, plaintext)[..16] == checksum
fn check_krb_rc4(h: &KrbHash, password: &str, usage: &[u8]) -> bool {
    let nt = nt_hash(password);
    let k1 = hmac_md5(&nt, usage);
    let k3 = hmac_md5(&k1, &h.checksum);
    let plain = rc4(&k3, &h.data);
    let verify = hmac_md5(&k1, &plain);
    verify[..16] == h.checksum[..]
}

fn check_asrep(h: &KrbHash, password: &str) -> bool {
    // usage = 8 (AS-REP encrypted part) — compatible hashcat 18200
    check_krb_rc4(h, password, b"\x08\x00\x00\x00")
}

fn check_tgs(h: &KrbHash, password: &str) -> bool {
    // usage = 2 (TGS-REP encrypted part) — compatible hashcat 13100
    check_krb_rc4(h, password, b"\x02\x00\x00\x00")
}

fn check_ntlm(expected: &str, password: &str) -> bool {
    hex::encode(nt_hash(password)) == expected
}

fn check_ntlmv2(h: &NtlmV2Hash, password: &str) -> bool {
    let nt = nt_hash(password);
    // NTLMv2 key = HMAC-MD5(NT, uppercase(user) + domain)
    let identity = format!("{}{}", h.user.to_uppercase(), h.domain);
    let ntv2_key = hmac_md5(&nt, identity.as_bytes());
    // response = HMAC-MD5(ntv2_key, server_chal || blob)
    let mut msg = h.server_chal.clone();
    msg.extend_from_slice(&h.blob);
    let computed = hmac_md5(&ntv2_key, &msg);
    computed == h.response.as_slice()
}

fn try_password(hash: &HashType, password: &str) -> bool {
    match hash {
        HashType::Asrep(h)  => check_asrep(h, password),
        HashType::Tgs(h)    => check_tgs(h, password),
        HashType::Ntlm(h)   => check_ntlm(h, password),
        HashType::NtlmV2(h) => check_ntlmv2(h, password),
    }
}

fn type_name(hash: &HashType) -> &'static str {
    match hash {
        HashType::Asrep(_)  => "asrep",
        HashType::Tgs(_)    => "tgs",
        HashType::Ntlm(_)   => "ntlm",
        HashType::NtlmV2(_) => "ntlmv2",
    }
}

fn raw_str(hash: &HashType) -> &str {
    match hash {
        HashType::Asrep(h)  => &h.raw,
        HashType::Tgs(h)    => &h.raw,
        HashType::Ntlm(h)   => h,
        HashType::NtlmV2(h) => &h.raw,
    }
}

// ── I/O ───────────────────────────────────────────────────────────────────────

fn load_wordlist(path: &str) -> std::io::Result<Vec<String>> {
    let f = File::open(path)?;
    Ok(BufReader::new(f)
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.is_empty())
        .collect())
}

fn load_hashes(path_or_hash: &str, fmt: &str) -> Vec<HashType> {
    if Path::new(path_or_hash).exists() {
        let f = File::open(path_or_hash).unwrap();
        return BufReader::new(f)
            .lines()
            .filter_map(|l| l.ok())
            .filter_map(|line| {
                let line = line.trim().to_string();
                if fmt == "auto" { parse_hash_auto(&line) } else { force_parse(&line, fmt) }
            })
            .collect();
    }
    if fmt == "auto" {
        parse_hash_auto(path_or_hash).into_iter().collect()
    } else {
        force_parse(path_or_hash, fmt).into_iter().collect()
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();

    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .unwrap();
    }

    let start = Instant::now();

    let hashes = load_hashes(&args.hash, &args.format);
    if hashes.is_empty() {
        eprintln!("Error: no se pudo parsear el hash. Comprueba el formato con -f asrep|tgs|ntlm|ntlmv2.");
        std::process::exit(1);
    }

    if !args.json_only {
        eprintln!(
            "[lobera-crack] {} hash(es) · tipo: {}",
            hashes.len(), type_name(&hashes[0])
        );
    }

    let words = match load_wordlist(&args.wordlist) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Error abriendo wordlist '{}': {}", args.wordlist, e);
            std::process::exit(1);
        }
    };
    let total = words.len() as u64;

    if !args.json_only {
        eprintln!("[lobera-crack] {} palabras", total);
    }

    let cracked  = Arc::new(Mutex::new(Vec::<CrackedEntry>::new()));
    let counter  = Arc::new(AtomicU64::new(0));
    let progress = args.progress;
    let quiet    = args.json_only;

    words.par_iter().for_each(|word| {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        if progress > 0 && !quiet && n > 0 && n % progress == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            eprintln!("[lobera-crack] {}/{} ({:.0}/s)", n, total, n as f64 / elapsed);
        }
        for hash in &hashes {
            if try_password(hash, word) {
                if !quiet {
                    eprintln!("[lobera-crack] ¡ENCONTRADO! {} → \"{}\"", type_name(hash), word);
                }
                cracked.lock().unwrap().push(CrackedEntry {
                    hash:      raw_str(hash).to_string(),
                    password:  word.clone(),
                    hash_type: type_name(hash).to_string(),
                });
            }
        }
    });

    let elapsed = start.elapsed().as_secs_f64();
    let result  = cracked.lock().unwrap().clone();
    let found   = result.len() as u64;

    if !quiet {
        eprintln!(
            "[lobera-crack] Fin: {}/{} en {:.2}s ({:.0}/s)",
            found, total, elapsed, total as f64 / elapsed
        );
    }

    println!("{}", serde_json::to_string_pretty(&Output {
        cracked: result,
        total,
        found,
        elapsed: format!("{:.2}s", elapsed),
    }).unwrap());
}
