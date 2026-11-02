// lib.rs — WASM export za risk-calib router (wasm32-wasip1 / wasm32-unknown-unknown).
//
// Kompajlira se u .wasm i poziva IN-PROCESS iz Pythona (wasmtime-py) BEZ
// proces-pipe round-tripa. To je prava prednost WASM-a: sandbox + determinizam
// + nema spawn overhead-a.
//
// Export funkcije (guest -> host memory):
//   route_json(ptr,len) -> ptr  (vrati pokazivac na JSON string u memoriji)
//   alloc(len) -> ptr           (host alocira buffer za unos)
//   free(ptr, len)               (host oslobodi)
//   last_len() -> i32           (duzina zadnjeg odgovora)

mod router;

use router::Router;

static mut OUT: Vec<u8> = Vec::new();

/// Alociraj buffer (host pise unos).
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v: Vec<u8> = Vec::with_capacity(len);
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Oslobodi buffer.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

/// Klasifikuj jedan zadatak; vrati pointer na JSON (i postavi last_len).
#[no_mangle]
pub unsafe extern "C" fn route_json(ptr: *const u8, len: usize) -> *mut u8 {
    let bytes = std::slice::from_raw_parts(ptr, len);
    let task = String::from_utf8_lossy(bytes).to_string();
    let r = Router::new();
    let val = r.route_with(&task, None, None);
    let s = serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string());
    OUT = s.into_bytes();
    OUT.as_mut_ptr()
}

/// Batch: ulaz = JSON array stringova; izlaz = JSON array rezultata.
#[no_mangle]
pub unsafe extern "C" fn route_batch_json(ptr: *const u8, len: usize) -> *mut u8 {
    let bytes = std::slice::from_raw_parts(ptr, len);
    let input = String::from_utf8_lossy(bytes).to_string();
    let tasks: Vec<String> = serde_json::from_str(&input).unwrap_or_default();
    let r = Router::new();
    let results: Vec<serde_json::Value> = tasks
        .iter()
        .map(|t| r.route_with(t, None, None))
        .collect();
    let s = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
    OUT = s.into_bytes();
    OUT.as_mut_ptr()
}

/// Duzina zadnjeg odgovora.
#[no_mangle]
pub extern "C" fn last_len() -> i32 {
    unsafe { OUT.len() as i32 }
}
