use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<InnerState>,
}

impl AppState {
    pub fn new(chall_dir: impl Into<PathBuf>) -> Self {
        let chall_dir = chall_dir.into();
        let inner = Arc::new(InnerState { chall_dir });
        AppState { inner }
    }

    pub fn chall_dir(&self) -> &Path {
        &self.inner.chall_dir
    }
}

struct InnerState {
    chall_dir: PathBuf,
}
