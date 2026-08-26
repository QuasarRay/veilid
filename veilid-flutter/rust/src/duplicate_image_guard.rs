//! Refuse to run as a second veilid_flutter image in one process.
//!
//! A rebuild can swap the library file on disk under a running process; a
//! later lazy symbol resolution then loads the new file as a SECOND image
//! with its own uninitialized statics, and calls into it hang forever. dlopen
//! cannot be made to fail from inside the library, so the load-time
//! constructor records/checks a process-wide marker and warns on stderr, and
//! `initialize_veilid_flutter` aborts loudly. Only one veilid-core image (of
//! any version) may be loaded per process; re-initialization of the SAME
//! image stays allowed (initialize is idempotent).

use std::ffi::CStr;
use std::sync::OnceLock;

/// Process-wide rendezvous. The env var is visible across images regardless
/// of dlopen flags; the pid qualifier keeps an inherited environment from
/// poisoning a fresh child process.
const MARKER_ENV: &str = "VEILID_FLUTTER_IMAGE_MARKER";

static DUPLICATE_OF: OnceLock<String> = OnceLock::new();

fn our_marker() -> String {
    format!(
        "{}:{:p}",
        std::process::id(),
        crate::dart_ffi::initialize_veilid_flutter as *const ()
    )
}

fn image_path_of(addr: *const libc::c_void) -> String {
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        if libc::dladdr(addr, &mut info) != 0 && !info.dli_fname.is_null() {
            return CStr::from_ptr(info.dli_fname)
                .to_string_lossy()
                .into_owned();
        }
    }
    "<unknown image>".to_owned()
}

/// The version string of the FIRST image, via its own exported function.
/// Apple's dlsym(RTLD_DEFAULT) searches all loaded images; elsewhere this may
/// miss RTLD_LOCAL loads and reports unknown.
fn first_image_description() -> String {
    unsafe {
        let first = libc::dlsym(
            libc::RTLD_DEFAULT,
            c"initialize_veilid_flutter".as_ptr().cast(),
        );
        let ours = crate::dart_ffi::initialize_veilid_flutter as *const libc::c_void;
        if first.is_null() || std::ptr::eq(first, ours) {
            return "<first image not resolvable>".to_owned();
        }
        let version = {
            let ver = libc::dlsym(libc::RTLD_DEFAULT, c"veilid_version_string".as_ptr().cast());
            if ver.is_null() {
                "<unknown version>".to_owned()
            } else {
                let f: extern "C" fn() -> *mut libc::c_char = std::mem::transmute(ver);
                // Deliberately leaked: freeing across images is not safe
                CStr::from_ptr(f()).to_string_lossy().into_owned()
            }
        };
        format!("{} (veilid-core {})", image_path_of(first), version)
    }
}

/// Some(description) when this image is a duplicate load in this process
pub fn duplicate_image() -> Option<&'static str> {
    DUPLICATE_OF.get().map(String::as_str)
}

extern "C" fn on_load() {
    let ours = our_marker();
    match std::env::var(MARKER_ENV) {
        Ok(prev) if prev != ours => {
            let our_pid = format!("{}:", std::process::id());
            if prev.starts_with(&our_pid) {
                // Same process, different image address: duplicate load
                let desc = format!(
                    "first image: {}; this image: {} (veilid-core {})",
                    first_image_description(),
                    image_path_of(
                        crate::dart_ffi::initialize_veilid_flutter as *const libc::c_void
                    ),
                    veilid_core::veilid_version_string(),
                );
                eprintln!(
                    "veilid-flutter: FATAL ON USE: a second veilid_flutter image was loaded \
                     into this process (a rebuild swapped the library file under a running \
                     app?). Initialization of this image will abort. {desc}"
                );
                let _ = DUPLICATE_OF.set(desc);
            } else {
                // Inherited from another process: claim it for ourselves
                unsafe { std::env::set_var(MARKER_ENV, &ours) };
            }
        }
        Err(_) => unsafe { std::env::set_var(MARKER_ENV, &ours) },
        _ => {}
    }
}

#[used]
#[cfg_attr(target_vendor = "apple", link_section = "__DATA,__mod_init_func")]
#[cfg_attr(not(target_vendor = "apple"), link_section = ".init_array")]
static ON_LOAD: extern "C" fn() = on_load;
