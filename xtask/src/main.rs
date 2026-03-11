use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
enum Commands {
    /// Generate stub files
    GenerateStubs { library: PathBuf },
}

fn main() -> testresult::TestResult {
    let cmd = Commands::parse();

    match cmd {
        Commands::GenerateStubs { library } => {
            let module = pyo3_introspection::introspect_cdylib(library, "pysequoia")?;
            let result = pyo3_introspection::module_stub_files(&module);
            let out_dir = PathBuf::from("python/pysequoia");
            std::fs::create_dir_all(&out_dir)?;
            for (path, content) in &result {
                let out_path = out_dir.join(path);
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out_path, content)?;
                println!("Wrote {}", out_path.display());
            }
        }
    }

    Ok(())
}
