use std::io::Result;

fn main() -> Result<()> {
    #[cfg(feature = "protobuf-src")]
    std::env::set_var("PROTOC", protobuf_src::protoc());

    prost_build::compile_protos(
        &["checkin.proto", "mcs.proto"],
        &["proto"],
    )?;

    Ok(())
}
