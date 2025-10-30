use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use tempfile::TempDir;

pub struct TempBinary {
    _dir: TempDir,
    path: PathBuf,
}

impl TempBinary {
    pub fn new(name: &str, source: &str) -> Self {
        let dir = TempDir::new().expect("create temp dir for binary");
        let src_path = dir.path().join(format!("{name}.rs"));
        std::fs::write(&src_path, source).expect("write temporary source file");

        let bin_path = dir
            .path()
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));

        let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
        let status = Command::new(rustc)
            .arg("--edition=2021")
            .arg(&src_path)
            .arg("-o")
            .arg(&bin_path)
            .status()
            .expect("invoke rustc");
        assert!(
            status.success(),
            "rustc failed to build temp binary with status {}",
            status
        );

        Self {
            _dir: dir,
            path: bin_path,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
