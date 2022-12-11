use bip32::DerivationPath;
use bip32::ChildNumber;

use clap::*;

use std::{str::FromStr};
use std::option::Option;
use std::io::Write;
use sui_types::crypto::{ SignatureScheme };
use sui_keys::key_derive::{validate_path, DERVIATION_PATH_PURPOSE_SECP256K1, DERIVATION_PATH_COIN_TYPE};
use fastcrypto::encoding::{Base64, Encoding};
use crate::wallets::{ Wallet, WalletError, prompt_password, confirm_password };
use crate::api::serve_api;
// util functions
fn prompt_input(prompt:&str) -> String {
    let mut line = String::new();
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut line).expect("Error: Could not read a line");

    return line.trim().to_string()
}

// commands
#[derive(Parser)]
#[clap(
    name = "suivault",
    about = "password protected sui wallet following the Web3 Secret Storage Definition",
    rename_all = "kebab-case",
)]
pub enum KsCommand {
    /// create a wallet, generate random seed
    #[clap(name = "random", about="create a wallet by generating random seeds")]
    Random {
         #[clap(short, long, help="wallet name", default_value="default")]
         wallet: String,
    },

    #[clap(name = "import", about="import a wallet using a phrase")]
    Import {
        #[clap(short, long, help="wallet name", default_value="default")]
         wallet: String,
    },

    #[clap(name = "new-address", about="create an address")]
    NewAddress {
        #[clap(short, long, help="wallet name", default_value="default")]
        wallet: String,

        #[clap(short, long, help="key scheme, ed25519 or secp256k1", default_value="ed25519")]
        key_scheme: String,

        #[clap(short, long, help="derivation path")]
        path: Option<String>,
    },

    #[clap(name = "new-mnemonic", about="generate a random mnemonic phrase")]
    NewMnemonic,

    #[clap(name = "sign", about="make a signature")]
    Sign {
        #[clap(short, long, help="wallet name", default_value="default")]
        wallet: String,

        #[clap(short, long, help="key scheme, ed25519 or secp256k1", default_value="ed25519")]
        key_scheme: String,

        #[clap(short, long, help="derivation path")]
        path: Option<String>,

        #[clap(short, long, help="base64 encoded data")]
        data: Option<String>,
    },

    #[clap(name = "serve-api", about="server a rest api")]
    ServeApi {
        #[clap(short, long, help="wallet name", default_value="default")]
        wallet: String,

        #[clap(short, long, help="server bind address", default_value="127.0.0.1:9030")]
        bind: String,

        #[clap(long, help="tls cert file")]
        cert_file: Option<String>,

        #[clap(long, help="tls key file")]
        key_file: Option<String>,

    },

    #[clap(name = "experiment", about = "do experiments")]
    Experiment,

}

impl KsCommand {
    pub async fn execute(self) -> Result<(), WalletError> {
        match self {
            KsCommand::Random {
                wallet,
            } => {
                if Wallet::wallet_exists(wallet.as_str()) {
                    return Err(WalletError::WalletAlreadyExist { wallet_name: wallet });
                }
                let password = prompt_password();
                if !confirm_password(password.clone()) {
                    println!("password not confirmed!");
                    return Ok(());
                }
                let w = Wallet::random(wallet.as_str(), password.clone())?;
                println!("Wallet {} created.", w.name());
                Ok(())
            },

            KsCommand::Import {
                wallet,
            } => {
                if Wallet::wallet_exists(wallet.as_str()) {
                    return Err(WalletError::WalletAlreadyExist { wallet_name: wallet });
                }

                let line = prompt_input("Input the phrase: ");
                let phrase = Wallet::get_mnemonic(line.as_str())?;

                println!("The mnemonic phrase is valid");
                let password = prompt_password();
                if !confirm_password(password.clone()) {
                    println!("password not confirmed!");
                    return Ok(());
                }
                let w = Wallet::from_phrase(wallet.as_str(), password.clone(), phrase)?;
                println!("Wallet {} created.", w.name());
                Ok(())
            },

            KsCommand::NewMnemonic => {
                let phrase = Wallet::new_mnemonic();
                println!("{}", phrase);
                Ok(())
            },

            KsCommand::NewAddress {
                wallet,
                key_scheme,
                path,
            } => {
                let sig_scheme = SignatureScheme::from_str(key_scheme.as_str())
                            .or_else(|e| Err(WalletError::ParamsError {
                                 message: format!("key scheme error, {}", e.to_string()),
                                }))?;

                if !Wallet::wallet_exists(wallet.as_str()) {
                    return Err(WalletError::WalletNotExist { wallet_name: wallet });
                }

                let password = prompt_password();
                let w = Wallet::load(wallet.as_str(), password.clone())?;
                let (addr, pubkey)= w.derive_address(&sig_scheme, path.clone())?;
                println!("Derivation path: {}", path.clone().unwrap_or("None".to_owned()));
                println!("Created address: {}", addr);
                println!("Public key: {}", Base64::encode(pubkey.as_ref()));
                Ok(())
            },

            KsCommand::Sign {
                wallet,
                key_scheme,
                path,
                data,
            } => {
                let sig_scheme = &SignatureScheme::from_str(
                            key_scheme.as_str())
                            .or_else(|e| Err(WalletError::ParamsError {
                                 message: format!("key scheme error, {}", e.to_string()),
                                    }))?;

                if data.is_none() {
                    return Err(WalletError::ParamsError {
                        message: "no data provided".to_owned()
                    });
                }

                let decoded = Base64::decode(data.unwrap().as_str()).or_else(|e| {
                    Err(WalletError::ParamsError {
                        message: format!("invalid data {}", e.to_string()),
                    })
                })?;

                if !Wallet::wallet_exists(wallet.as_str()) {
                    return Err(WalletError::WalletNotExist { wallet_name: wallet });
                }
                let password = prompt_password();
                let w = Wallet::load(wallet.as_str(), password.clone())?;
                let sig = w.sign(&sig_scheme, path, decoded.as_slice())?;

                println!("Key Scheme: {}", sig.signature_scheme()?);
                println!("Public Key Base64: {}", sig.public_key());
                println!("Signature: {}", sig.signature());
                Ok(())
            },

            KsCommand::ServeApi {
                wallet,
                bind,
                cert_file,
                key_file,
            } => {
                if !Wallet::wallet_exists(wallet.as_str()) {
                    return Err(WalletError::WalletNotExist { wallet_name: wallet });
                }
                let password = prompt_password();
                let w = Wallet::load(wallet.as_str(), password.clone())?;
                serve_api(w, bind, cert_file, key_file).await;
                Ok(())
            },

            KsCommand::Experiment => {
                let key_scheme = &SignatureScheme::Secp256k1;
                let path = DerivationPath::from_str("m/54'/784'/0'/0/3").unwrap();
                //let &[purpose, coin_type, account, change, address] = path.as_ref();
                let chunks = path.as_ref();
                for item in chunks.into_iter() {
                    println!("{}, {}", item.index(), item.is_hardened());
                }
                if chunks[0] == ChildNumber::new(DERVIATION_PATH_PURPOSE_SECP256K1, true).unwrap() {
                    println!("purpose eq");
                }

                if chunks[1] == ChildNumber::new(DERIVATION_PATH_COIN_TYPE, true).unwrap() {
                    println!("coin_type eq");
                }

                if chunks[2].is_hardened() {
                    println!("account is hardened");
                }

                if chunks[3].is_hardened() {
                    println!("change is hardened");
                }

                if chunks[4].is_hardened() {
                    println!("address is hardened");
                }

                let r = validate_path(key_scheme, Some(path));
                println!("validate {:?}", r);
                Ok(())
            }
        }
    }
}

