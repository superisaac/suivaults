// refers to https://docs.rs/eth-keystore/latest/eth_keystore/fn.encrypt_key.html


use std::path::{PathBuf};
use std::fs::create_dir_all;
use bip32::secp256k1::elliptic_curve::zeroize::Zeroize;
use home::home_dir;
use std::sync::Arc;

use rpassword;
use thiserror::{Error as ThisError};
use bip32::{DerivationPath, Mnemonic, Language};
use eth_keystore::{encrypt_key, decrypt_key, KeystoreError};
use fastcrypto::encoding::{Base64, Encoding};
use sui_keys::key_derive::derive_key_pair_from_path;
use sui_types::crypto::{SignatureScheme, SuiKeyPair };
use sui_types::base_types::SuiAddress;
use sui_types::error::SuiError;
use signature::{ Signer, Error as SigError};
use signature::rand_core::OsRng;
use core::str::FromStr;

#[derive(Clone)]
pub struct SigResult {
    flag: Vec<u8>,
    signature: String,
    public_key: String,
}

impl SigResult {
    pub fn public_key(&self) -> String {
        self.public_key.clone()
    }

    pub fn signature(&self) -> String {
        self.signature.clone()
    }

    pub fn flag_byte(&self) -> u8 {
        self.flag[0]
    }

    pub fn flag(&self) -> Vec<u8> {
        self.flag.clone()
    }

    pub fn signature_scheme(&self) -> Result<SignatureScheme, WalletError> {
        signature_scheme_from_u8(self.flag_byte())
    }

}

// WalletError
#[derive(ThisError, Debug)]
pub enum WalletError {
    #[error("encrypt wallet error")]
    EncryptWallet(KeystoreError),

    #[error("decrypt wallet error")]
    DecryptWallet(KeystoreError),

    #[error("signature error")]
    Signature(SigError),

    #[error("parse derivation path error")]
    DerivationPath { message: String},

    #[error("sui error")]
    Sui(SuiError),

    #[error("wallet not exist")]
    WalletNotExist { wallet_name: String },

    #[error("wallet already exist")]
    WalletAlreadyExist { wallet_name: String },

    #[error("io error")]
    IoError { message: String},

    #[error("params error")]
    ParamsError { message: String},
}

// util functions
fn parse_derive_path(path: Option<String>) -> Result<Option<DerivationPath>, WalletError> {
    match path {
        None => Ok(None),
        Some(s) => match DerivationPath::from_str(s.as_str()) {
            Ok(dp) => Ok(Some(dp)),
            Err(err) => Err(WalletError::DerivationPath {
                message: err.to_string()
            })
        }
    }
}

pub fn prompt_password() -> String {
    rpassword::prompt_password("Input the wallet password: ").unwrap()
}

pub fn confirm_password(password: String) -> bool {
    let confirm = rpassword::prompt_password("Confirm the wallet password: ").unwrap();
    return confirm == password;
}

fn wallet_directory() -> PathBuf {
    return home_dir().unwrap().join(".keystore");
}

pub fn signature_scheme_from_u8(value: u8) -> Result<SignatureScheme, WalletError> {
    if value == 0 {
        Ok(SignatureScheme::ED25519)
    } else if value == 1 {
        Ok(SignatureScheme::Secp256k1)
    } else if value == 0xff {
        Ok(SignatureScheme::BLS12381)
    } else {
        Err(WalletError::ParamsError { message: "invalid sig scheme bytes".to_owned() })
    }
}

// Password protected wallet file
#[derive(Clone)]
pub struct Wallet {
    name: String,
    secret: Vec<u8>,
}

impl Wallet {
    pub fn wallet_exists(name: &str) -> bool {
        wallet_directory().join(name.to_owned() + ".json").exists()
    }
    
    pub fn new_mnemonic() -> String {
        let mnemonic = Mnemonic::random(OsRng, Language::English);
        return mnemonic.phrase().to_owned();
    }

    // generate random private key and save to file
    pub fn random(name: &str, password: String) -> Result<Arc<Self>, WalletError> {
        let mnemonic = Mnemonic::random(OsRng, Language::English);
        let seed = mnemonic.to_seed("");
        let secret = seed.as_bytes().to_vec();

        let wallet = Arc::new(Wallet {
            name: String::from(name),
            secret: secret,
        });
        wallet.clone().save_key(password)?;
        Ok(wallet)
    }

    pub fn get_mnemonic(p: &str) -> Result<Mnemonic, WalletError> {
        Mnemonic::new(p, Language::English)
        .or_else(|e| Err(WalletError::ParamsError {
            message: format!("invalie mnemonic phrase {:?}", e),
        }))
    }

    // generate random private key and save to file
    pub fn from_phrase(name: &str, password: String, mnemonic: Mnemonic) -> Result<Arc<Self>, WalletError> {
        let seed = mnemonic.to_seed("");
        let secret = seed.as_bytes().to_vec();

        let wallet = Arc::new(Wallet {
            name: String::from(name),
            secret: secret,
        });
        wallet.clone().save_key(password)?;
        Ok(wallet)
    }

    fn save_key(&self, password: String) -> Result<(), WalletError> {
        //let mut rng = rand::thread_rng();
        let file_name = self.name.clone() + ".json";
        let dir = wallet_directory();
        if !dir.clone().exists() {
            create_dir_all(dir.clone())
            .or_else(|e| Err(WalletError::IoError { 
                message: e.to_string()
            }))?;
        }
        if dir.clone().join(file_name.clone()).exists() {
            return Err(WalletError::WalletAlreadyExist {
                wallet_name: self.name.clone()
            });
        }
        encrypt_key(
            &dir,
            &mut OsRng,
            self.secret.clone(),
            password,
            Some(file_name.clone().as_str()))
        .and_then(|_| Ok(()))
        .or_else(|e| Err(WalletError::EncryptWallet(e)))
    }

    // load from wallet file
    pub fn load(name: &str, password: String) -> Result<Arc<Self>, WalletError> {
        let file_path = wallet_directory().join(name.to_owned() + ".json");

        if !file_path.exists() {
            return Err(WalletError::WalletNotExist { 
                wallet_name: name.to_owned()
            });
        }
        match decrypt_key(file_path.as_os_str(), password) {
            Ok(decrypted) => Ok(Arc::new(Wallet {
                    name: name.to_owned(),
                    secret: decrypted,
                })),
            Err(err) => return Err(WalletError::DecryptWallet(err))
        }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    fn derive_key_pair(&self, key_scheme: &SignatureScheme, derive_path: Option<String>) -> Result<(SuiAddress, SuiKeyPair), WalletError> {
        let dpath = parse_derive_path(derive_path)?;
        derive_key_pair_from_path(
            self.secret.as_slice(),
            dpath,
            key_scheme).or_else(|err| Err(WalletError::Sui(err)))
    }

    pub fn sign(&self, key_scheme: &SignatureScheme, derive_path: Option<String>, data: &[u8]) -> Result<SigResult, WalletError> {
        let (_, key_pair) = self.derive_key_pair(key_scheme, derive_path)?;

        let sig_joined = key_pair.try_sign(data)
                                    .or_else(|err| Err(WalletError::Signature(err)))?;

        let signature_string = format!("{:?}", sig_joined);

        // signature string is the conjunction of [flag, sig, public key] using '@'.
        let sig_split = signature_string.split('@').collect::<Vec<_>>();
        let (flag, signature, pub_key) = 
        if let [flag, signature, pub_key] = sig_split.as_slice() { 
            (flag, signature, pub_key) 
        } else {
             panic!("bad signature string {}", signature_string);
        };

        let decoded_flag = Base64::decode(*flag).unwrap();

        Ok(SigResult { 
            flag: decoded_flag, 
            signature: (*signature).to_owned(),
            public_key: (*pub_key).to_owned()
        })
    }

    pub fn create_address(&self, key_scheme: &SignatureScheme, derive_path: Option<String>) -> Result<SuiAddress, WalletError> {
        let (addr, _) = self.derive_key_pair(key_scheme, derive_path)?;
        Ok(addr)
    }

}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

