use std::sync::Arc;
use veilid_core::{
    api_startup, VeilidAPI, VeilidConfig, VeilidConfigProtectedStore, VeilidConfigTableStore,
    VeilidUpdate,
};

pub struct BenchContext {
    pub veilid: VeilidAPI,
    pub rt: tokio::runtime::Runtime,
    _temp_dir: tempfile::TempDir,
}

impl BenchContext {
    pub fn new() -> Self {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let temp_dir = tempfile::TempDir::new().expect("Failed to create temp dir");
        let root_path = temp_dir.path();

        let path_to_string = |p: std::path::PathBuf| -> String { p.to_string_lossy().into_owned() };

        let veilid = rt.block_on(async {
            let update_callback = Arc::new(|_: VeilidUpdate| {});
            let config = VeilidConfig {
                program_name: "bench".into(),
                namespace: "bench".into(),
                protected_store: VeilidConfigProtectedStore {
                    always_use_insecure_storage: true,
                    directory: path_to_string(root_path.join("protected")),
                    ..Default::default()
                },
                table_store: VeilidConfigTableStore {
                    directory: path_to_string(root_path.join("table")),
                    ..Default::default()
                },
                ..Default::default()
            };
            api_startup(update_callback, config).await.unwrap()
        });

        Self {
            veilid,
            rt,
            _temp_dir: temp_dir,
        }
    }
}

impl Default for BenchContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BenchContext {
    fn drop(&mut self) {
        let veilid = self.veilid.clone();
        self.rt.block_on(async move {
            veilid.shutdown().await;
        });
    }
}
