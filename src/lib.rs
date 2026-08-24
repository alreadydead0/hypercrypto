pub mod aes_ctr;
pub mod aes_ige;
pub mod kdf_core;
pub mod pack_core;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use sha2::{Digest, Sha256};

use crate::aes_ctr::Aes256CtrState;
use crate::aes_ige as ige_internal;
use crate::kdf_core as kdf_internal;
use crate::pack_core as pack_internal;

const GIL_RELEASE_THRESHOLD: usize = 16384;

struct RawSlice(*mut u8, usize);
unsafe impl Send for RawSlice {}

impl RawSlice {
    #[inline(always)]
    unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.0, self.1)
    }
}

/// Ultra-fast SHA-256
#[pyfunction]
#[pyo3(signature = (data))]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let result = Sha256::digest(data);
    PyBytes::new(py, &result)
}

/// AES-256-IGE Encryption (Zero-Rust-Heap-Allocation via PyBytes::new_with)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_encrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data length must be a multiple of 16"));
    }
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    PyBytes::new_with(py, data.len(), |buf| {
        buf.copy_from_slice(data);
        if buf.len() >= GIL_RELEASE_THRESHOLD {
            let mut raw = RawSlice(buf.as_mut_ptr(), buf.len());
            py.allow_threads(move || {
                let s = unsafe { raw.as_mut_slice() };
                ige_internal::ige256_encrypt_inplace(s, &key_arr, &iv_arr);
            });
        } else {
            ige_internal::ige256_encrypt_inplace(buf, &key_arr, &iv_arr);
        }
        Ok(())
    })
}

/// AES-256-IGE Decryption (Zero-Rust-Heap-Allocation via PyBytes::new_with)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_decrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data length must be a multiple of 16"));
    }
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    PyBytes::new_with(py, data.len(), |buf| {
        buf.copy_from_slice(data);
        if buf.len() >= GIL_RELEASE_THRESHOLD {
            let mut raw = RawSlice(buf.as_mut_ptr(), buf.len());
            py.allow_threads(move || {
                let s = unsafe { raw.as_mut_slice() };
                ige_internal::ige256_decrypt_inplace(s, &key_arr, &iv_arr);
            });
        } else {
            ige_internal::ige256_decrypt_inplace(buf, &key_arr, &iv_arr);
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

/// AES-256-CTR Encryption / Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ctr256_encrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 16] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 16 bytes"))?;

    PyBytes::new_with(py, data.len(), |buf| {
        buf.copy_from_slice(data);
        if buf.len() >= GIL_RELEASE_THRESHOLD {
            let mut raw = RawSlice(buf.as_mut_ptr(), buf.len());
            py.allow_threads(move || {
                let s = unsafe { raw.as_mut_slice() };
                let mut state = Aes256CtrState::new(&key_arr, &iv_arr);
                state.process_inplace(s);
            });
        } else {
            let mut state = Aes256CtrState::new(&key_arr, &iv_arr);
            state.process_inplace(buf);
        }
        Ok(())
    })
}

/// AES-256-CTR Decryption (Symmetric to encryption)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ctr256_decrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    ctr256_encrypt(py, data, key, iv)
}

/// In-Place AES-256-CTR Processing
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ctr256_encrypt_inplace(py: Python<'_>, data: &Bound<'_, PyByteArray>, key: &[u8], iv: &[u8]) -> PyResult<()> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 16] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 16 bytes"))?;

    let slice = unsafe { data.as_bytes_mut() };
    if slice.len() >= GIL_RELEASE_THRESHOLD {
        let mut raw = RawSlice(slice.as_mut_ptr(), slice.len());
        py.allow_threads(move || {
            let s = unsafe { raw.as_mut_slice() };
            let mut state = Aes256CtrState::new(&key_arr, &iv_arr);
            state.process_inplace(s);
        });
    } else {
        let mut state = Aes256CtrState::new(&key_arr, &iv_arr);
        state.process_inplace(slice);
    }
    Ok(())
}

/// In-Place AES-256-CTR Decryption (Alias)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ctr256_decrypt_inplace(py: Python<'_>, data: &Bound<'_, PyByteArray>, key: &[u8], iv: &[u8]) -> PyResult<()> {
    ctr256_encrypt_inplace(py, data, key, iv)
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
/// Optimized with PyBytes::new_with (Zero Rust heap allocations)
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
        pack_internal::pack_message_into(&auth_arr, message, is_outgoing, buf);
        Ok(())
    })
}

/// Unpack MTProto 2.0 Message (AES-IGE Decrypt -> MsgKey Check)
/// Optimized with PyBytes::new_with (Zero Rust heap allocations)
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
        match pack_internal::unpack_message_into(&auth_arr, encrypted_packet, is_outgoing, buf) {
            Ok(_) => Ok(()),
            Err(e) => {
                err_msg = Some(e);
                Ok(())
            }
        }
    })?;

    if let Some(e) = err_msg {
        return Err(PyValueError::new_err(e));
    }
    Ok(res)
}

/// HyperCrypto Python C-Extension Module
#[pymodule]
fn hypercrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.1")?;
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
    Ok(())
}
