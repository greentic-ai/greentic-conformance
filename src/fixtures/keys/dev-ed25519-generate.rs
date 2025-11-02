fn main() {
    use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    std::fs::write("dev-ed25519.key", signing_key.to_bytes()).expect("write signing key");
    std::fs::write("dev-ed25519.pub", verifying_key.to_bytes()).expect("write verifying key");

    println!(
        "Wrote dev-ed25519.key ({SECRET_KEY_LENGTH} bytes) and dev-ed25519.pub ({} bytes)",
        verifying_key.to_bytes().len()
    );
}
