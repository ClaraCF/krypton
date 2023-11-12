use krypton;

fn main() {

    let password = b"Super_s3cure_P4s5w0rd123!!";
    let plaintext = b"This is a message lmao";

    let ciphertext = krypton::encrypt(password, plaintext);
    let decrypted = krypton::decrypt(password, &ciphertext);

    let ciphertext = krypton::base64_encode(&ciphertext);

    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext: {}", ciphertext);
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}
