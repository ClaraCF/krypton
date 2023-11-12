use rand_core::{RngCore, OsRng};
use pbkdf2::pbkdf2_hmac;
use sha3::Sha3_512;
use serde::{self, Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};

const PBKDF_ITERATIONS: u32 = 1000;

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // First perform a round of encryption using ChaCha
    let chacha_ciphertext = cha_encrypt(key, plaintext);
    
    // Serialize the result into bytes
    let intermediate_ciphertext = bincode::serialize::<EncryptedCha>(&chacha_ciphertext)
        .expect("Serialize ChaCha ciphertext");

    // Encrypt the resulting ciphertext with AES
    let aes_ciphertext = aes_encrypt(key, &intermediate_ciphertext);

    // Return the serialized output as bytes
    bincode::serialize::<EncryptedAes>(&aes_ciphertext)
        .expect("Serialize AES ciphertext")
}

pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    // println!("[DEBUG] {:#?}", ciphertext);

    // First deserialize the input into an AES ciphertext
    let aes_ciphertext = bincode::deserialize::<EncryptedAes>(ciphertext)
        .expect("Deserialize AES ciphertext");

    let aes_key = AesKey::new_from_meta(key, aes_ciphertext.meta);
    
    // Decrypt the ciphertext
    let intermediate_ciphertext = aes_decrypt(&aes_key, &aes_ciphertext.ciphertext);
    
    // Deserialize the intermediate ChaCha ciphertext
    let chacha_ciphertext = bincode::deserialize::<EncryptedCha>(&intermediate_ciphertext)
        .expect("Deserialize ChaCha ciphertext");

    let chacha_key = ChaKey::new_from_meta(key, chacha_ciphertext.meta);

    // Return the decrypted ChaCha ciphertext
    cha_decrypt(&chacha_key, &chacha_ciphertext.ciphertext)
}

pub fn base64_encode(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn base64_decode(input: String) -> Vec<u8> {
    general_purpose::STANDARD.decode(input)
        .expect("Decode Base64 string")
}

fn cha_encrypt(key: &[u8], plaintext: &[u8]) -> EncryptedCha {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305,
    };

    // // Create a cryptographically-secure random nonce
    // let mut chacha_nonce = [0u8; 24];
    // OsRng.fill_bytes(&mut chacha_nonce);
    //
    // // Create a cryptographically-secure random salt
    // let mut chacha_salt = [0u8; 32];
    // OsRng.fill_bytes(&mut chacha_salt);
    //
    // // Derive a key from the master key
    // let mut chacha_key = [0u8; 32];
    // pbkdf2_hmac::<Sha3_512>(key, &chacha_salt, PBKDF_ITERATIONS, &mut chacha_key);
    // pbkdf2_hmac::<Sha3_512>(&chacha_key.clone(), &chacha_nonce, PBKDF_ITERATIONS, &mut chacha_key);

    // Generate a random, cryptographically-secure key
    let chacha_key = ChaKey::new(key);

    let cipher = XChaCha20Poly1305::new(&chacha_key.key.into());

    EncryptedCha {
        // TODO: Handle unwrap
        ciphertext: cipher.encrypt(&chacha_key.meta.nonce.into(), plaintext).unwrap(),
        meta: ChaMeta {
            nonce: chacha_key.meta.nonce,
            salt: chacha_key.meta.salt,
            iterations: chacha_key.meta.iterations,
        }
    }
}

fn cha_decrypt(key: &ChaKey, ciphertext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305,
    };

    // Derive the decryption key from the master key
    // let mut chacha_key = [0u8; 32];
    // pbkdf2_hmac::<Sha3_512>(key, &ciphertext.salt, PBKDF_ITERATIONS, &mut chacha_key);
    // pbkdf2_hmac::<Sha3_512>(&chacha_key.clone(), &ciphertext.nonce, PBKDF_ITERATIONS, &mut chacha_key);


    let cipher = XChaCha20Poly1305::new(&key.key.into());

    cipher.decrypt(&key.meta.nonce.into(), ciphertext).expect("Decrypt ChaCha ciphertext")
}

fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> EncryptedAes {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm,
    };

    // // Create a cryptographically-secure random nonce
    // let mut aes_nonce = [0u8; 12];
    // OsRng.fill_bytes(&mut aes_nonce);
    //
    // // Create a cryptographically-secure random salt
    // let mut aes_salt = [0u8; 32];
    // OsRng.fill_bytes(&mut aes_salt);
    //
    // // Derive a key from the master key
    // let mut aes_key = [0u8; 32];
    // pbkdf2_hmac::<Sha3_512>(key, &aes_salt, PBKDF_ITERATIONS, &mut aes_key);
    // pbkdf2_hmac::<Sha3_512>(&aes_key.clone(), &aes_nonce, PBKDF_ITERATIONS, &mut aes_key);

    // Generate a new, cryptographically-secure key
    let aes_key = AesKey::new(key);

    let cipher = Aes256Gcm::new(&aes_key.key.into());

    EncryptedAes {
        // TODO: Handle unwrap
        ciphertext: cipher.encrypt(&aes_key.meta.nonce.into(), plaintext).unwrap(),
        meta: AesMeta {
            nonce: aes_key.meta.nonce,
            salt: aes_key.meta.salt,
            iterations: aes_key.meta.iterations,
        }
    }
}

fn aes_decrypt(key: &AesKey, ciphertext: &[u8]) -> Vec<u8> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm,
    };

    // Derive the decryption key from the master key
    // let mut aes_key = [0u8; 32];
    // pbkdf2_hmac::<Sha3_512>(key, &ciphertext.salt, PBKDF_ITERATIONS, &mut aes_key);
    // pbkdf2_hmac::<Sha3_512>(&aes_key.clone(), &ciphertext.nonce, PBKDF_ITERATIONS, &mut aes_key);


    let cipher = Aes256Gcm::new(&key.key.into());

    match cipher.decrypt(&key.meta.nonce.into(), ciphertext) {
        Err(err) => panic!("Failed to decrypt AES ciphertext: {}", err),
        Ok(plaintext) => plaintext,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AesMeta {
    nonce: [u8; 12],    // 96 bits, 12 bytes
    salt: [u8; 32],     // 256 bits, 32 bytes
    iterations: u32,    // Number of PBKDF2 iterations
}

#[derive(Debug, Serialize, Deserialize)]
struct ChaMeta {
    nonce: [u8; 24],    // 192 bits, 24 bytes
    salt: [u8; 32],     // 256 bits, 32 bytes
    iterations: u32,    // Number of PBKDF2 iterations
}

struct AesKey {
    key: [u8; 32],      // The actual key. 256 bits, 32 bytes
    meta: AesMeta,      // Values used for the encryption
}

struct ChaKey {
    key: [u8; 32],      // The actual key. 256 bits, 32 bytes
    meta: ChaMeta,      // Values used for the encryption
}


#[derive(Debug, Serialize, Deserialize)]
struct EncryptedAes {
    ciphertext: Vec<u8>,
    meta: AesMeta,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedCha {
    ciphertext: Vec<u8>,
    meta: ChaMeta,
}

impl AesKey {
    fn new(master_key: &[u8]) -> Self {
        // Create a cryptographically-secure random nonce
        let mut aes_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut aes_nonce);

        // Create a cryptographically-secure random salt
        let mut aes_salt = [0u8; 32];
        OsRng.fill_bytes(&mut aes_salt);

        // Derive a key from the master key
        let mut aes_key = [0u8; 32];
        pbkdf2_hmac::<Sha3_512>(master_key, &aes_salt, PBKDF_ITERATIONS/2, &mut aes_key);
        pbkdf2_hmac::<Sha3_512>(&aes_key.clone(), &aes_nonce, PBKDF_ITERATIONS/2, &mut aes_key);
        
        AesKey {
            key: aes_key,
            meta: AesMeta {
                nonce: aes_nonce,
                salt: aes_salt,
                iterations: PBKDF_ITERATIONS,
            }
        }
    }

    fn new_from_meta(master_key: &[u8], meta: AesMeta) -> Self {
        AesKey {
            key: AesKey::derive_key(master_key, &meta),
            meta,
        }
    }

    fn derive_key(master_key: &[u8], params: &AesMeta) -> [u8; 32] {
        let mut aes_key = [0u8; 32];
        pbkdf2_hmac::<Sha3_512>(master_key, &params.salt, params.iterations/2, &mut aes_key);
        pbkdf2_hmac::<Sha3_512>(&aes_key.clone(), &params.nonce, params.iterations/2, &mut aes_key);

        aes_key
    }
}

impl ChaKey {
    fn new(master_key: &[u8]) -> Self {
        // Create a cryptographically-secure random nonce
        let mut cha_nonce = [0u8; 24];
        OsRng.fill_bytes(&mut cha_nonce);

        // Create a cryptographically-secure random salt
        let mut cha_salt = [0u8; 32];
        OsRng.fill_bytes(&mut cha_salt);

        // Derive a key from the master key
        let mut cha_key = [0u8; 32];
        pbkdf2_hmac::<Sha3_512>(master_key, &cha_salt, PBKDF_ITERATIONS/2, &mut cha_key);
        pbkdf2_hmac::<Sha3_512>(&cha_key.clone(), &cha_nonce, PBKDF_ITERATIONS/2, &mut cha_key);
        
        ChaKey {
            key: cha_key,
            meta: ChaMeta {
                nonce: cha_nonce,
                salt: cha_salt,
                iterations: PBKDF_ITERATIONS,
            }
        }
    }

    fn new_from_meta(master_key: &[u8], meta: ChaMeta) -> Self {
        ChaKey {
            key: ChaKey::derive_key(master_key, &meta),
            meta,
        }
    }

    fn derive_key(master_key: &[u8], params: &ChaMeta) -> [u8; 32] {
        let mut chacha_key = [0u8; 32];
        pbkdf2_hmac::<Sha3_512>(master_key, &params.salt, params.iterations/2, &mut chacha_key);
        pbkdf2_hmac::<Sha3_512>(&chacha_key.clone(), &params.nonce, params.iterations/2, &mut chacha_key);

        chacha_key
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn encrypt_works() {
        //let result = encrypt();
        //assert_eq!(result, ());
    }

    #[test]
    fn decrypt_works() {
        //let result = decrypt();
        //assert_eq!(result, ());
    }
}

