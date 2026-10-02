use std::{error::Error, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new("../../schemas/protobuf");
    let schema = root.join("apollo/telemetry/v1/telemetry.proto");
    println!("cargo:rerun-if-changed={}", schema.display());
    prost_build::Config::new()
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .compile_protos(&[schema], &[root])?;
    Ok(())
}
