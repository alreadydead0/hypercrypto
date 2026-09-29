#![allow(clippy::manual_is_multiple_of, clippy::needless_range_loop)]

pub mod aes_ctr;
pub mod aes_ige;
pub mod kdf_core;
pub mod pack_core;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use sha2::{Digest, Sha256};

use crate::aes_ctr as ctr_internal;
use crate::aes_ige as ige_internal;
use crate::kdf_core as kdf_internal;
use crate::pack_core as pack_internal;

const GIL_RELEASE_THRESHOLD: usize = 65536;

struct RawSlice(*mut u8, usize);
unsafe impl Send for RawSlice {}

impl RawSlice {
    #[inline(always)]
    unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.0, self.1)
    }
}

struct RawConstSlice(*const u8, usize);
unsafe impl Send for RawConstSlice {}

impl RawConstSlice {
    #[inline(always)]
    unsafe fn as_slice(&self) -> &[u8] {
        std::slice::from_raw_parts(self.0, self.1)
    }
}

/// Ultra-fast SHA-256
#[pyfunction]
#[pyo3(signature = (data))]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let result = Sha256::digest(data);
    PyBytes::new(py, &result)
}

/// AES-256-IGE Encryption (Zero-Rust-Heap-Allocation via single-pass PyBytes::new_with)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_encrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data length must be a multiple of 16"));
    }

    PyBytes::new_with(py, data.len(), |buf| {
        if buf.len() >= GIL_RELEASE_THRESHOLD {
            let in_raw = RawConstSlice(data.as_ptr(), data.len());
            let mut out_raw = RawSlice(buf.as_mut_ptr(), buf.len());
            py.allow_threads(move || {
                let src = unsafe { in_raw.as_slice() };
                let dst = unsafe { out_raw.as_mut_slice() };
                ige_internal::ige256_encrypt_slice(src, dst, &key_arr, &iv_arr);
            });
        } else {
            ige_internal::ige256_encrypt_slice(data, buf, &key_arr, &iv_arr);
        }
        Ok(())
    })
}

/// AES-256-IGE Decryption (Zero-Rust-Heap-Allocation via single-pass PyBytes::new_with)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_decrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data length must be a multiple of 16"));
    }

    PyBytes::new_with(py, data.len(), |buf| {
        if buf.len() >= GIL_RELEASE_THRESHOLD {
            let in_raw = RawConstSlice(data.as_ptr(), data.len());
            let mut out_raw = RawSlice(buf.as_mut_ptr(), buf.len());
            py.allow_threads(move || {
                let src = unsafe { in_raw.as_slice() };
                let dst = unsafe { out_raw.as_mut_slice() };
                ige_internal::ige256_decrypt_slice(src, dst, &key_arr, &iv_arr);
            });
        } else {
            ige_internal::ige256_decrypt_slice(data, buf, &key_arr, &iv_arr);
        }
        Ok(())
    })
}

/// In-Place AES-256-IGE Encryption
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_encrypt_inplace(py: Python<'_>, data: &Bound<'_, PyByteArray>, key: &[u8], iv: &[u8]) -> PyResult<()> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    let slice = unsafe { data.as_bytes_mut() };
    if slice.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data length must be a multiple of 16"));
    }
    if slice.len() >= GIL_RELEASE_THRESHOLD {
        let mut raw = RawSlice(slice.as_mut_ptr(), slice.len());
        py.allow_threads(move || {
            let s = unsafe { raw.as_mut_slice() };
            ige_internal::ige256_encrypt_inplace(s, &key_arr, &iv_arr);
        });
    } else {
        ige_internal::ige256_encrypt_inplace(slice, &key_arr, &iv_arr);
    }
    Ok(())
}

/// In-Place AES-256-IGE Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_decrypt_inplace(py: Python<'_>, data: &Bound<'_, PyByteArray>, key: &[u8], iv: &[u8]) -> PyResult<()> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    let slice = unsafe { data.as_bytes_mut() };
    if slice.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data length must be a multiple of 16"));
    }
    if slice.len() >= GIL_RELEASE_THRESHOLD {
        let mut raw = RawSlice(slice.as_mut_ptr(), slice.len());
        py.allow_threads(move || {
            let s = unsafe { raw.as_mut_slice() };
            ige_internal::ige256_decrypt_inplace(s, &key_arr, &iv_arr);
        });
    } else {
        ige_internal::ige256_decrypt_inplace(slice, &key_arr, &iv_arr);
    }
    Ok(())
}

/// AES-256-CTR Encryption / Decryption with In-Place IV and State updates
#[pyfunction]
#[pyo3(signature = (data, key, iv, state = None))]
fn ctr256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &Bound<'_, PyAny>,
    state: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;

    let is_iv_bytearray = iv.is_instance_of::<PyByteArray>();
    let mut iv_arr = [0u8; 16];
    if is_iv_bytearray {
        let ba = iv.downcast::<PyByteArray>()?;
        let slice = unsafe { ba.as_bytes() };
        if slice.len() < 16 {
            return Err(PyValueError::new_err("IV must be at least 16 bytes"));
        }
        iv_arr.copy_from_slice(&slice[..16]);
    } else {
        let b = iv.extract::<&[u8]>()?;
        if b.len() < 16 {
            return Err(PyValueError::new_err("IV must be at least 16 bytes"));
        }
        iv_arr.copy_from_slice(&b[..16]);
    }

    let mut st_arr = [0u8; 1];
    let is_st_bytearray = if let Some(st) = state {
        if st.is_instance_of::<PyByteArray>() {
            let ba = st.downcast::<PyByteArray>()?;
            let slice = unsafe { ba.as_bytes() };
            if !slice.is_empty() {
                st_arr[0] = slice[0];
            }
            true
        } else {
            let b = st.extract::<&[u8]>()?;
            if !b.is_empty() {
                st_arr[0] = b[0];
            }
            false
        }
    } else {
        false
    };

    let mut updated_iv = iv_arr;
    let mut updated_st = st_arr;

    let res = PyBytes::new_with(py, data.len(), |buf| {
        if data.len() >= GIL_RELEASE_THRESHOLD {
            let mut raw_out = RawSlice(buf.as_mut_ptr(), buf.len());
            let in_raw = RawConstSlice(data.as_ptr(), data.len());
            let res = py.allow_threads(move || {
                let out_slice = unsafe { raw_out.as_mut_slice() };
                let in_slice = unsafe { in_raw.as_slice() };
                ctr_internal::ctr256_process(in_slice, &key_arr, &mut iv_arr, &mut st_arr, out_slice);
                (iv_arr, st_arr)
            });
            updated_iv = res.0;
            updated_st = res.1;
        } else {
            ctr_internal::ctr256_process(data, &key_arr, &mut updated_iv, &mut updated_st, buf);
        }
        Ok(())
    })?;

    if is_iv_bytearray {
        let ba = iv.downcast::<PyByteArray>()?;
        let slice = unsafe { ba.as_bytes_mut() };
        slice[..16].copy_from_slice(&updated_iv);
    }

    if is_st_bytearray {
        if let Some(st) = state {
            let ba = st.downcast::<PyByteArray>()?;
            let slice = unsafe { ba.as_bytes_mut() };
            if !slice.is_empty() {
                slice[0] = updated_st[0];
            }
        }
    }

    Ok(res)
}

/// AES-256-CTR Decryption (Symmetric to encryption)
#[pyfunction]
#[pyo3(signature = (data, key, iv, state = None))]
fn ctr256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &Bound<'_, PyAny>,
    state: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyBytes>> {
    ctr256_encrypt(py, data, key, iv, state)
}

/// In-Place AES-256-CTR Processing
#[pyfunction]
#[pyo3(signature = (data, key, iv, state = None))]
fn ctr256_encrypt_inplace(
    py: Python<'_>,
    data: &Bound<'_, PyByteArray>,
    key: &[u8],
    iv: &Bound<'_, PyAny>,
    state: Option<&Bound<'_, PyAny>>,
) -> PyResult<()> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;

    let is_iv_bytearray = iv.is_instance_of::<PyByteArray>();
    let mut iv_arr = [0u8; 16];
    if is_iv_bytearray {
        let ba = iv.downcast::<PyByteArray>()?;
        let slice = unsafe { ba.as_bytes() };
        if slice.len() < 16 {
            return Err(PyValueError::new_err("IV must be at least 16 bytes"));
        }
        iv_arr.copy_from_slice(&slice[..16]);
    } else {
        let b = iv.extract::<&[u8]>()?;
        if b.len() < 16 {
            return Err(PyValueError::new_err("IV must be at least 16 bytes"));
        }
        iv_arr.copy_from_slice(&b[..16]);
    }

    let mut st_arr = [0u8; 1];
    let is_st_bytearray = if let Some(st) = state {
        if st.is_instance_of::<PyByteArray>() {
            let ba = st.downcast::<PyByteArray>()?;
            let slice = unsafe { ba.as_bytes() };
            if !slice.is_empty() {
                st_arr[0] = slice[0];
            }
            true
        } else {
            let b = st.extract::<&[u8]>()?;
            if !b.is_empty() {
                st_arr[0] = b[0];
            }
            false
        }
    } else {
        false
    };

    let slice = unsafe { data.as_bytes_mut() };
    if slice.len() >= GIL_RELEASE_THRESHOLD {
        let mut raw = RawSlice(slice.as_mut_ptr(), slice.len());
        let res = py.allow_threads(move || {
            let s = unsafe { raw.as_mut_slice() };
            ctr_internal::ctr256_process_inplace(s, &key_arr, &mut iv_arr, &mut st_arr);
            (iv_arr, st_arr)
        });
        iv_arr = res.0;
        st_arr = res.1;
    } else {
        ctr_internal::ctr256_process_inplace(slice, &key_arr, &mut iv_arr, &mut st_arr);
    }

    if is_iv_bytearray {
        let ba = iv.downcast::<PyByteArray>()?;
        let s = unsafe { ba.as_bytes_mut() };
        s[..16].copy_from_slice(&iv_arr);
    }

    if is_st_bytearray {
        if let Some(st) = state {
            let ba = st.downcast::<PyByteArray>()?;
            let s = unsafe { ba.as_bytes_mut() };
            if !s.is_empty() {
                s[0] = st_arr[0];
            }
        }
    }

    Ok(())
}

/// In-Place AES-256-CTR Decryption (Alias)
#[pyfunction]
#[pyo3(signature = (data, key, iv, state = None))]
fn ctr256_decrypt_inplace(
    py: Python<'_>,
    data: &Bound<'_, PyByteArray>,
    key: &[u8],
    iv: &Bound<'_, PyAny>,
    state: Option<&Bound<'_, PyAny>>,
) -> PyResult<()> {
    ctr256_encrypt_inplace(py, data, key, iv, state)
}

/// MTProto 2.0 KDF (Key Derivation Function) - Returns (aes_key: bytes, aes_iv: bytes)
#[pyfunction]
#[pyo3(signature = (auth_key, msg_key, is_outgoing))]
fn kdf<'py>(
    py: Python<'py>,
    auth_key: &[u8],
    msg_key: &[u8],
    is_outgoing: bool,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let auth_arr: [u8; 256] = auth_key
        .try_into()
        .map_err(|_| PyValueError::new_err("auth_key must be 256 bytes"))?;
    let msg_arr: [u8; 16] = msg_key
        .try_into()
        .map_err(|_| PyValueError::new_err("msg_key must be 16 bytes"))?;

    let (aes_key, aes_iv) = kdf_internal::kdf_calc(&auth_arr, &msg_arr, is_outgoing);
    Ok((PyBytes::new(py, &aes_key), PyBytes::new(py, &aes_iv)))
}

/// MTProto 2.0 In-Place KDF (Zero-Allocation Ultra Low Latency)
#[pyfunction]
#[pyo3(signature = (auth_key, msg_key, is_outgoing, key_out, iv_out))]
fn kdf_into(
    _py: Python<'_>,
    auth_key: &[u8],
    msg_key: &[u8],
    is_outgoing: bool,
    key_out: &Bound<'_, PyByteArray>,
    iv_out: &Bound<'_, PyByteArray>,
) -> PyResult<()> {
    let auth_arr: [u8; 256] = auth_key
        .try_into()
        .map_err(|_| PyValueError::new_err("auth_key must be 256 bytes"))?;
    let msg_arr: [u8; 16] = msg_key
        .try_into()
        .map_err(|_| PyValueError::new_err("msg_key must be 16 bytes"))?;

    let (aes_key, aes_iv) = kdf_internal::kdf_calc(&auth_arr, &msg_arr, is_outgoing);

    let k_slice = unsafe { key_out.as_bytes_mut() };
    if k_slice.len() < 32 {
        return Err(PyValueError::new_err("key_out must be at least 32 bytes"));
    }
    k_slice[..32].copy_from_slice(&aes_key);

    let iv_slice = unsafe { iv_out.as_bytes_mut() };
    if iv_slice.len() < 32 {
        return Err(PyValueError::new_err("iv_out must be at least 32 bytes"));
    }
    iv_slice[..32].copy_from_slice(&aes_iv);

    Ok(())
}

/// Pack MTProto 2.0 Message (Padding -> MsgKey -> KDF -> AES-IGE)
#[pyfunction]
#[pyo3(signature = (auth_key, message, is_outgoing))]
fn pack_message<'py>(
    py: Python<'py>,
    auth_key: &[u8],
    message: &[u8],
    is_outgoing: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let auth_arr: [u8; 256] = auth_key
        .try_into()
        .map_err(|_| PyValueError::new_err("auth_key must be 256 bytes"))?;
    let msg_len = message.len();
    let padding_len = 16 - (msg_len % 16);
    let total_padding = if padding_len < 12 { padding_len + 16 } else { padding_len };
    let total_len = 16 + msg_len + total_padding;

    PyBytes::new_with(py, total_len, |buf| {
        if total_len >= GIL_RELEASE_THRESHOLD {
            let mut raw_buf = RawSlice(buf.as_mut_ptr(), buf.len());
            let msg_raw = RawConstSlice(message.as_ptr(), message.len());
            py.allow_threads(move || {
                let out_slice = unsafe { raw_buf.as_mut_slice() };
                let msg_slice = unsafe { msg_raw.as_slice() };
                pack_internal::pack_message_into(&auth_arr, msg_slice, is_outgoing, out_slice);
            });
        } else {
            pack_internal::pack_message_into(&auth_arr, message, is_outgoing, buf);
        }
        Ok(())
    })
}

/// Unpack MTProto 2.0 Message (AES-IGE Decrypt -> MsgKey Check)
#[pyfunction]
#[pyo3(signature = (auth_key, encrypted_packet, is_outgoing))]
fn unpack_message<'py>(
    py: Python<'py>,
    auth_key: &[u8],
    encrypted_packet: &[u8],
    is_outgoing: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    if encrypted_packet.len() < 32 {
        return Err(PyValueError::new_err("Encrypted packet too short"));
    }
    let auth_arr: [u8; 256] = auth_key
        .try_into()
        .map_err(|_| PyValueError::new_err("auth_key must be 256 bytes"))?;
    let payload_len = encrypted_packet.len() - 16;

    let mut err_msg: Option<&'static str> = None;
    let res = PyBytes::new_with(py, payload_len, |buf| {
        if payload_len >= GIL_RELEASE_THRESHOLD {
            let mut raw_buf = RawSlice(buf.as_mut_ptr(), buf.len());
            let pkt_raw = RawConstSlice(encrypted_packet.as_ptr(), encrypted_packet.len());
            let err = py.allow_threads(move || {
                let out_slice = unsafe { raw_buf.as_mut_slice() };
                let pkt_slice = unsafe { pkt_raw.as_slice() };
                pack_internal::unpack_message_into(&auth_arr, pkt_slice, is_outgoing, out_slice).err()
            });
            err_msg = err;
        } else {
            match pack_internal::unpack_message_into(&auth_arr, encrypted_packet, is_outgoing, buf) {
                Ok(_) => {},
                Err(e) => { err_msg = Some(e); }
            }
        }
        Ok(())
    })?;

    if let Some(e) = err_msg {
        return Err(PyValueError::new_err(e));
    }
    Ok(res)
}

/// Set hardware dispatch mode override for testing/benchmarks
/// Modes: "portable", "aesni", "vaes256", "vaes512", or None to reset to auto
#[pyfunction]
#[pyo3(signature = (mode = None))]
fn _set_force_mode(mode: Option<&str>) -> PyResult<()> {
    match mode {
        Some(m) => {
            let val = match m.trim().to_lowercase().as_str() {
                "vaes512" | "vaes-512" | "512" => ctr_internal::MODE_VAES512,
                "vaes256" | "vaes-256" | "256" => ctr_internal::MODE_VAES256,
                "aesni" | "ni" | "sse" => ctr_internal::MODE_AESNI,
                "portable" | "fallback" => ctr_internal::MODE_PORTABLE,
                _ => return Err(PyValueError::new_err(format!("Invalid force mode: {m}. Valid modes: portable, aesni, vaes256, vaes512"))),
            };
            ctr_internal::set_dispatch_override(val);
        }
        None => {
            ctr_internal::set_dispatch_override(ctr_internal::MODE_UNINIT);
        }
    }
    Ok(())
}

/// Get currently active hardware dispatch mode
#[pyfunction]
fn _get_force_mode() -> &'static str {
    match ctr_internal::get_dispatch_override() {
        ctr_internal::MODE_VAES512 => "vaes512",
        ctr_internal::MODE_VAES256 => "vaes256",
        ctr_internal::MODE_AESNI => "aesni",
        ctr_internal::MODE_PORTABLE => "portable",
        _ => "unknown",
    }
}

/// Check if the host CPU supports a specific hardware instruction feature
#[pyfunction]
fn _has_cpu_feature(feature: &str) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        match feature.to_lowercase().as_str() {
            "vaes" => is_x86_feature_detected!("vaes"),
            "avx512f" => is_x86_feature_detected!("avx512f"),
            "avx512vl" => is_x86_feature_detected!("avx512vl"),
            "avx512bw" => is_x86_feature_detected!("avx512bw"),
            "avx2" => is_x86_feature_detected!("avx2"),
            "aes" => is_x86_feature_detected!("aes"),
            "sse2" => is_x86_feature_detected!("sse2"),
            "ssse3" => is_x86_feature_detected!("ssse3"),
            _ => false,
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = feature;
        false
    }
}

/// HyperCrypto Python C-Extension Module
#[pymodule]
fn hypercrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.5")?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_encrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(kdf, m)?)?;
    m.add_function(wrap_pyfunction!(kdf_into, m)?)?;
    m.add_function(wrap_pyfunction!(pack_message, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_message, m)?)?;
    m.add_function(wrap_pyfunction!(_set_force_mode, m)?)?;
    m.add_function(wrap_pyfunction!(_get_force_mode, m)?)?;
    m.add_function(wrap_pyfunction!(_has_cpu_feature, m)?)?;
    Ok(())
}
