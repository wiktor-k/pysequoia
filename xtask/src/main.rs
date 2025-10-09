use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
enum Commands {
    /// Generate stub file (pysequoia.pyi)
    GenerateStubs { library: PathBuf },
}

fn main() -> testresult::TestResult {
    let cmd = Commands::parse();

    match cmd {
        Commands::GenerateStubs { library } => {
            let module = pyo3_introspection::introspect_cdylib(library, "pysequoia")?;
            let result = pyo3_introspection::module_stub_files(&module);
            println!("{result:?}");
            let value = result
                .get(&PathBuf::from("__init__.pyi"))
                .expect("stubs to be there");
            std::fs::write("pysequoia.pyi", value)?;
        }
    }

    Ok(())
}
