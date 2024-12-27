use clap::{Arg, Command};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::sync::mpsc;

#[derive(Clone)]
struct EncryptionParams {
    key: u8,
    signing_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SecurePackage {
    data: Vec<u8>,
    signature: Vec<u8>,
    salt: Vec<u8>,
}

// custom error type
#[derive(Debug)]
enum ProcessError {
    InvalidFormat(String),
    SecurityError(String),
    IoError(io::Error),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProcessError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            ProcessError::SecurityError(msg) => write!(f, "Security error: {}", msg),
            ProcessError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl Error for ProcessError {}

impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        ProcessError::IoError(error)
    }
}

impl From<serde_json::Error> for ProcessError {
    fn from(_: serde_json::Error) -> Self {
        ProcessError::InvalidFormat(
            "File is not in the correct format or was not encrypted with this program".to_string(),
        )
    }
}

// component trait defining the interface for all components
trait Component {
    fn process(&self, input: Vec<u8>, params: &EncryptionParams) -> Result<Vec<u8>, ProcessError>;
}

// file reader component
struct FileReader;
impl FileReader {
    fn new() -> Self {
        FileReader
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, ProcessError> {
        let mut file = fs::File::open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        Ok(content)
    }
}

// XOR encryption component
struct XorProcessor;
impl XorProcessor {
    fn new() -> Self {
        XorProcessor
    }
}

impl Component for XorProcessor {
    fn process(
        &self,
        mut input: Vec<u8>,
        params: &EncryptionParams,
    ) -> Result<Vec<u8>, ProcessError> {
        for byte in input.iter_mut() {
            *byte ^= params.key;
        }
        Ok(input)
    }
}

// signature component
struct SignatureProcessor {
    mode: SignatureMode,
}

enum SignatureMode {
    Generate,
    Verify,
}

impl SignatureProcessor {
    fn new(mode: SignatureMode) -> Self {
        SignatureProcessor { mode }
    }

    fn generate_signature(data: &[u8], signing_key: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(signing_key);
        hasher.update(salt);
        hasher.finalize().to_vec()
    }

    fn verify_signature(data: &[u8], signing_key: &[u8], salt: &[u8], signature: &[u8]) -> bool {
        let calculated_signature = Self::generate_signature(data, signing_key, salt);
        calculated_signature == signature
    }
}

impl Component for SignatureProcessor {
    fn process(&self, input: Vec<u8>, params: &EncryptionParams) -> Result<Vec<u8>, ProcessError> {
        match self.mode {
            SignatureMode::Generate => {
                let mut salt = vec![0u8; 16];
                rand::thread_rng().fill_bytes(&mut salt);

                let signature = Self::generate_signature(&input, &params.signing_key, &salt);
                let package = SecurePackage {
                    data: input,
                    signature,
                    salt,
                };
                Ok(serde_json::to_vec(&package).map_err(|_| {
                    ProcessError::InvalidFormat("Failed to package the encrypted data".to_string())
                })?)
            }
            SignatureMode::Verify => {
                let package: SecurePackage = serde_json::from_slice(&input)?;
                if !Self::verify_signature(
                    &package.data,
                    &params.signing_key,
                    &package.salt,
                    &package.signature,
                ) {
                    return Err(ProcessError::SecurityError(
                        "Security verification failed - file may have been tampered with"
                            .to_string(),
                    ));
                }
                Ok(package.data)
            }
        }
    }
}

// file writer component
struct FileWriter;
impl FileWriter {
    fn new() -> Self {
        FileWriter
    }

    fn write(&self, path: &str, content: &[u8]) -> Result<(), ProcessError> {
        fs::write(path, content)?;
        Ok(())
    }
}

// network coordinator
struct Network {
    reader: FileReader,
    writer: FileWriter,
    components: Vec<Box<dyn Component>>,
}

impl Network {
    fn new(components: Vec<Box<dyn Component>>) -> Self {
        Network {
            reader: FileReader::new(),
            writer: FileWriter::new(),
            components,
        }
    }

    fn process(
        &self,
        input_path: &str,
        output_path: &str,
        params: &EncryptionParams,
    ) -> Result<(), ProcessError> {
        let (tx, rx) = mpsc::channel();

        // read initial data
        let initial_data = self.reader.read(input_path)?;
        tx.send(initial_data).map_err(|_| {
            ProcessError::InvalidFormat("Failed to process data through components".to_string())
        })?;

        // process through components
        let mut final_data = rx.recv().map_err(|_| {
            ProcessError::InvalidFormat("Failed to receive data from components".to_string())
        })?;

        for component in &self.components {
            final_data = component.process(final_data, params)?;
        }

        // write result
        self.writer.write(output_path, &final_data)?;
        Ok(())
    }
}

fn derive_signing_key(encryption_key: u8) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&[encryption_key]);
    hasher.finalize().to_vec()
}

fn main() {
    let matches = Command::new("xen")
        .version("1.0")
        .about("Encrypts and decrypts files using XOR encryption with secure digital signatures")
        .arg(
            Arg::new("file")
                .help("The file to encrypt or decrypt")
                .required(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("key")
                .help("The XOR key to use for encryption/decryption")
                .required(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("decrypt")
                .help("Decrypt the file instead of encrypting")
                .short('d')
                .long("decrypt")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let file_path = matches.get_one::<String>("file").unwrap();
    let key: u8 = matches
        .get_one::<String>("key")
        .unwrap()
        .parse()
        .expect("Invalid key value");
    let decrypt = matches.get_flag("decrypt");

    let params = EncryptionParams {
        key,
        signing_key: derive_signing_key(key),
    };

    let output_path = if decrypt {
        format!("{}_decrypted", file_path)
    } else {
        format!("{}_encrypted", file_path)
    };

    let components: Vec<Box<dyn Component>> = if decrypt {
        vec![
            Box::new(XorProcessor::new()),
            Box::new(SignatureProcessor::new(SignatureMode::Verify)),
        ]
    } else {
        vec![
            Box::new(SignatureProcessor::new(SignatureMode::Generate)),
            Box::new(XorProcessor::new()),
        ]
    };

    let network = Network::new(components);
    match network.process(file_path, &output_path, &params) {
        Ok(()) => println!(
            "{} completed. Output saved to {}",
            if decrypt { "Decryption" } else { "Encryption" },
            output_path
        ),
        Err(e) => eprintln!("Error: {}", e),
    }
}
