fn main() {
    use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
    use rand::{rng, RngCore};

    let mut secret = [0u8; SECRET_KEY_LENGTH];
    let mut rng = rng();
    rng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    std::fs::write("dev-ed25519.key", signing_key.to_bytes()).expect("write signing key");
    std::fs::write("dev-ed25519.pub", verifying_key.to_bytes()).expect("write verifying key");

    println!(
        "Wrote dev-ed25519.key ({SECRET_KEY_LENGTH} bytes) and dev-ed25519.pub ({} bytes)",
        verifying_key.to_bytes().len()
    );
}
