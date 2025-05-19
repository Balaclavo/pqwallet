use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use hex;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use std::fs::{File, metadata};
use std::io::{Write, Read};
use serde::{Serialize, Deserialize};
use rpassword::read_password;
use std::process::exit;
use std::io;

#[derive(Serialize, Deserialize)]
struct KeyData {
    public_key: String,
    private_key: String,
    address: String,
}

fn ask_unique_filename() -> String {
    loop {
        println!("Enter wallet name (without extension):");
        let mut wallet_name = String::new();
        io::stdin().read_line(&mut wallet_name).expect("Failed to read input");
        let wallet_name = wallet_name.trim();
        if wallet_name.is_empty() {
            println!("Wallet name cannot be empty.");
            continue;
        }

        let filename = format!("{}.json.enc", wallet_name);
        if metadata(&filename).is_ok() {
            println!("❌ File '{}' already exists. Please choose another name.", filename);
            continue;
        } else {
            return filename;
        }
    }
}

fn create_new() {
    let filename = ask_unique_filename();

    println!("Enter your password:");
    let password = read_password().expect("Failed to read password");

    println!("Confirm your password:");
    let confirm = read_password().expect("Failed to read password");

    if password != confirm {
        eprintln!("❌ Passwords do not match. Exiting.");
        exit(1);
    }

    println!("✅ Password received.");

    let key_bytes = Sha256::digest(password.as_bytes());
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let (public_key, private_key) = dilithium5::keypair();
    let public_key_bytes = public_key.as_bytes();
    let private_key_bytes = private_key.as_bytes();

    let hash = Sha256::digest(public_key_bytes);
    let address = &hash[0..20];

    let key_data = KeyData {
        public_key: hex::encode(public_key_bytes),
        private_key: hex::encode(private_key_bytes),
        address: format!("pq{}", hex::encode(address)),
    };

    let plaintext = serde_json::to_vec(&key_data).expect("❌ Failed to serialize KeyData");

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .expect("❌ Encryption failed");

    let mut file = File::create(&filename).expect("❌ Failed to create file");
    file.write_all(&nonce).expect("❌ Failed to write nonce");
    file.write_all(&ciphertext).expect("❌ Failed to write ciphertext");

    println!("🔐 Encrypted keys saved to '{}'", filename);
}

fn decrypt(filename: &str, password: &str) -> Result<KeyData, String> {
    //##isolate the decryption logic here
    let mut file = File::open(filename).map_err(|_| format!("❌ Failed to open file '{}'", filename))?;
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data).map_err(|_| "❌ Failed to read file".to_string())?;

    if file_data.len() < 12 {
        return Err("❌ File too short to contain nonce + ciphertext.".to_string());
    }

    let (nonce_bytes, ciphertext) = file_data.split_at(12);

    let key_bytes = Sha256::digest(password.as_bytes());
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| "❌ Decryption failed - wrong password or corrupted file".to_string())?;

    let key_data: KeyData = serde_json::from_slice(&plaintext).map_err(|_| "❌ Failed to parse JSON".to_string())?;

    Ok(key_data)
}

fn decrypt_and_print() {
    //#replace the decryption logic here for the decrypt() function after implementing it. keep it printing the results in terminal.
    println!("Enter the encrypted filename (default: keys.json.enc):");
    let mut filename = String::new();
    io::stdin().read_line(&mut filename).expect("Failed to read input");
    let filename = filename.trim();
    let filename = if filename.is_empty() { "keys.json.enc" } else { filename };

    if metadata(filename).is_err() {
        eprintln!("❌ File '{}' not found.", filename);
        return;
    }

    println!("Enter your password:");
    let password = read_password().expect("Failed to read password");

    match decrypt(filename, &password) {
        Ok(key_data) => {
            println!("🔓 Decrypted Key Data:");
            println!("Public Key: {}", key_data.public_key);
            println!("Private Key: {}", key_data.private_key);
            println!("Address: {}", key_data.address);
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn open_in_gedit() {
    //#replace the decryption logic here for the decrypt() function after implementing it keep it openning in gedit.
    println!("Enter the encrypted filename (e.g., wallet.json.enc):");
    let mut enc_filename = String::new();
    io::stdin().read_line(&mut enc_filename).expect("Failed to read input");
    let enc_filename = enc_filename.trim();

    if enc_filename.is_empty() {
        println!("❌ Filename cannot be empty.");
        return;
    }

    if metadata(enc_filename).is_err() {
        println!("❌ File '{}' not found.", enc_filename);
        return;
    }

    println!("Enter your password:");
    let password = read_password().expect("Failed to read password");

    match decrypt(enc_filename, &password) {
        Ok(key_data) => {
            let plaintext = serde_json::to_vec(&key_data).expect("❌ Failed to serialize KeyData");

            let temp_filename = enc_filename.strip_suffix(".enc").unwrap_or(enc_filename);
            let mut temp_file = match File::create(temp_filename) {
                Ok(f) => f,
                Err(_) => {
                    eprintln!("❌ Failed to create temporary file '{}'", temp_filename);
                    return;
                }
            };

            temp_file.write_all(&plaintext).expect("❌ Failed to write decrypted content");

            match std::process::Command::new("gedit").arg(temp_filename).spawn() {
                Ok(_) => println!("📂 Opening decrypted file '{}' in gedit...", temp_filename),
                Err(e) => eprintln!("❌ Failed to open file in gedit: {}", e),
            }
        }
        Err(e) => eprintln!("{}", e),
    }
}


fn main() {
    // ASCII Art with #PurepoW.site
    println!(r#"
_________                                   _________ _______
\_   ___ \_______  ____ ______  ___________ \_   ___ \\      \
/    \  \/\_  __ \/  _ \\____ \/ __ \_  __ \/    \  \/ /  |   \
\     \____|  | \(  <_> )  |_> >  ___/|  | \/\     \____/   |  \
 \______  /|__|   \____/|   __/ \___  >__|    \______  /\______|
        \/              |__|        \/               \/
                #Visit: http://purepow.site
    "#);

    // Crypto Mining related ASCII art
    println!(r#"
      /------------\
     |  ----------  |
     | | [][][][][] | |
     | | [][][][][] | |
     | | [][][][][] | |
     |  ----------  |
      \------------/
        /  \  /  \
       /____\/____\
    "#);

    println!("Select option:");
    println!("(1) Create new encrypted wallet file");
    println!("(2) Decrypt and open in gedit");
    println!("(3) Decrypt and open in command line");
    println!("_________________________________________________________________________________________________________________________________________________________");	
    println!("##-> WARNING: When choosing the GEDIT option you need to delete the  decrypted file (your_wallet_name.json)  created in the root directory of the app!!! ");
    println!("_________________________________________________________________________________________________________________________________________________________");

 	

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).expect("Failed to read input");

    match choice.trim() {
        "1" => create_new(),
        "2" => open_in_gedit(), // Renamed function
        "3" => decrypt_and_print(),
        _ => println!("Invalid option"),
    }
}
