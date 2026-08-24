pub mod aes_ctr;
pub mod aes_ige;
pub mod kdf_engine;
pub mod pack_engine;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use ring::digest::{digest, SHA256};

use crate::aes_ctr::Aes256CtrState;
use crate::aes_ige as ige_internal;
use crate::kdf_engine as kdf_internal;
use crate::pack_engine as pack_internal;

struct RawSlice(*mut u8, usize);
unsafe impl Send for RawSlice {}

impl RawSlice {
    unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.0, self.1)
    }
}

/// Ultra-fast SHA-256 using CPU assembly
#[pyfunction]
#[pyo3(signature = (data))]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let d = digest(&SHA256, data);
    PyBytes::new(py, d.as_ref())
}

/// AES-256-IGE Encryption (Returns newly allocated bytes)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_encrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data length must be a multiple of 16"));
    }
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    let mut buf = data.to_vec();
    if data.len() >= 16384 {
        py.allow_threads(|| {
            ige_internal::ige256_encrypt_inplace(&mut buf, &key_arr, &iv_arr);
        });
    } else {
        ige_internal::ige256_encrypt_inplace(&mut buf, &key_arr, &iv_arr);
    }

    Ok(PyBytes::new(py, &buf))
}

/// AES-256-IGE Decryption (Returns newly allocated bytes)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_decrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err("Data length must be a multiple of 16"));
    }
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    let mut buf = data.to_vec();
    if data.len() >= 16384 {
        py.allow_threads(|| {
            ige_internal::ige256_decrypt_inplace(&mut buf, &key_arr, &iv_arr);
        });
    } else {
        ige_internal::ige256_decrypt_inplace(&mut buf, &key_arr, &iv_arr);
    }

    Ok(PyBytes::new(py, &buf))
}

/// In-Place AES-256-IGE Encryption (Zero-copy mutation on bytearray)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_encrypt_inplace(py: Python<'_>, data: &Bound<'_, PyAny>, key: &[u8], iv: &[u8]) -> PyResult<()> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    if let Ok(bytearray) = data.downcast::<PyByteArray>() {
        let slice = unsafe { bytearray.as_bytes_mut() };
        if slice.len() % 16 != 0 {
            return Err(PyValueError::new_err("Data length must be a multiple of 16"));
        }
        if slice.len() >= 16384 {
            let mut raw = RawSlice(slice.as_mut_ptr(), slice.len());
            py.allow_threads(move || {
                let s = unsafe { raw.as_mut_slice() };
                ige_internal::ige256_encrypt_inplace(s, &key_arr, &iv_arr);
            });
        } else {
            ige_internal::ige256_encrypt_inplace(slice, &key_arr, &iv_arr);
        }
        Ok(())
    } else {
        Err(PyTypeError::new_err("data must be a mutable bytearray"))
    }
}

/// In-Place AES-256-IGE Decryption (Zero-copy mutation on bytearray)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_decrypt_inplace(py: Python<'_>, data: &Bound<'_, PyAny>, key: &[u8], iv: &[u8]) -> PyResult<()> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 32] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;

    if let Ok(bytearray) = data.downcast::<PyByteArray>() {
        let slice = unsafe { bytearray.as_bytes_mut() };
        if slice.len() % 16 != 0 {
            return Err(PyValueError::new_err("Data length must be a multiple of 16"));
        }
        if slice.len() >= 16384 {
            let mut raw = RawSlice(slice.as_mut_ptr(), slice.len());
            py.allow_threads(move || {
                let s = unsafe { raw.as_mut_slice() };
                ige_internal::ige256_decrypt_inplace(s, &key_arr, &iv_arr);
            });
        } else {
            ige_internal::ige256_decrypt_inplace(slice, &key_arr, &iv_arr);
        }
        Ok(())
    } else {
        Err(PyTypeError::new_err("data must be a mutable bytearray"))
    }
}

/// AES-256-CTR Encryption / Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ctr256_encrypt<'py>(py: Python<'py>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 16] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 16 bytes"))?;

    let mut buf = data.to_vec();
    if data.len() >= 16384 {
        py.allow_threads(|| {
            let mut state = Aes256CtrState::new(&key_arr, &iv_arr);
            state.process_inplace(&mut buf);
        });
    } else {
        let mut state = Aes256CtrState::new(&key_arr, &iv_arr);
        state.process_inplace(&mut buf);
    }

    Ok(PyBytes::new(py, &buf))
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
fn ctr256_encrypt_inplace(py: Python<'_>, data: &Bound<'_, PyAny>, key: &[u8], iv: &[u8]) -> PyResult<()> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
    let iv_arr: [u8; 16] = iv.try_into().map_err(|_| PyValueError::new_err("IV must be 16 bytes"))?;

    if let Ok(bytearray) = data.downcast::<PyByteArray>() {
        let slice = unsafe { bytearray.as_bytes_mut() };
        if slice.len() >= 16384 {
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
    } else {
        Err(PyTypeError::new_err("data must be a mutable bytearray"))
    }
}

/// In-Place AES-256-CTR Decryption (Alias)
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ctr256_decrypt_inplace(py: Python<'_>, data: &Bound<'_, PyAny>, key: &[u8], iv: &[u8]) -> PyResult<()> {
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

    let (aes_key, aes_iv) = kdf_internal::kdf(&auth_arr, &msg_arr, is_outgoing);
    Ok((PyBytes::new(py, &aes_key), PyBytes::new(py, &aes_iv)))
}

/// MTProto 2.0 In-Place KDF (Zero-Allocation Ultra Low Latency)
/// Writes (aes_key, aes_iv) directly into pre-allocated bytearrays without Python heap allocations!
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

    let (aes_key, aes_iv) = kdf_internal::kdf(&auth_arr, &msg_arr, is_outgoing);

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
    let packed = pack_internal::pack_message(&auth_arr, message, is_outgoing);
    Ok(PyBytes::new(py, &packed))
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
    let auth_arr: [u8; 256] = auth_key
        .try_into()
        .map_err(|_| PyValueError::new_err("auth_key must be 256 bytes"))?;
    match pack_internal::unpack_message(&auth_arr, encrypted_packet, is_outgoing) {
        Ok(unpacked) => Ok(PyBytes::new(py, &unpacked)),
        Err(err) => Err(PyValueError::new_err(err)),
    }
}

/// HyperCrypto Python C-Extension Module
#[pymodule]
fn hypercrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
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
