use super::*;

use jni::{errors::Result as JniResult, objects::Global, objects::JObject, EnvUnowned, JavaVM};
use lazy_static::*;

pub struct AndroidGlobals {
    pub vm: JavaVM,
    pub ctx: Global<JObject<'static>>,
}

impl Drop for AndroidGlobals {
    fn drop(&mut self) {
        // Ensure we're attached before dropping Global
        self.vm
            .attach_current_thread(|_| JniResult::Ok(()))
            .unwrap_or_log();
    }
}

lazy_static! {
    pub static ref ANDROID_GLOBALS: Arc<Mutex<Option<AndroidGlobals>>> = Arc::new(Mutex::new(None));
}

pub fn veilid_core_setup_android(mut env: EnvUnowned, ctx: JObject) {
    env.with_env(|env| -> JniResult<()> {
        let ctx = env.new_global_ref(ctx)?;
        let vm = env.get_java_vm()?;
        *ANDROID_GLOBALS.lock() = Some(AndroidGlobals { vm, ctx });
        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>();
}

pub fn is_android_ready() -> bool {
    ANDROID_GLOBALS.lock().is_some()
}

pub fn get_android_globals() -> (JavaVM, Global<JObject<'static>>) {
    let globals_locked = ANDROID_GLOBALS.lock();
    let globals = globals_locked.as_ref().unwrap_or_log();
    globals
        .vm
        .attach_current_thread(|env| {
            let vm = env.get_java_vm().unwrap_or_log();
            let ctx = env.new_global_ref(globals.ctx.as_obj()).unwrap_or_log();
            JniResult::Ok((vm, ctx))
        })
        .unwrap_or_log()
}
