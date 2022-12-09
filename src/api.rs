use axum::{Form, Json, Router};
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::response::IntoResponse;
use axum::http::StatusCode;

use std::sync::Arc;
use std::str::FromStr;
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use sui_types::crypto::{ SignatureScheme };
use fastcrypto::encoding::{Base64, Encoding};

use crate::ks_wallet::Wallet;

pub async fn serve_api(wallet: Arc<Wallet>, server_bind: String) {
    let app = Router::new()
              .route("/addresses", post(create_address))
              .route("/addresses/:key_scheme/m/:purpose/:coin_type/:account/:change/:index", get(get_address))
              .route("/signatures", post(make_signature))
              .with_state(wallet);

    let addr = SocketAddr::from_str(server_bind.as_str()).unwrap();
    println!("api server starts at http://{}, available endpoints are POST /addresses and POST /signatures ", server_bind);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// create address
#[derive(Deserialize)]
struct CreateAddressRequest {
    key_scheme: String,
    derivation_path: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct CreateAddressResponse {
    derivation_path: String,
    address: String
}

#[derive(Deserialize)]
struct GetAddressParams {
    key_scheme: String,
    purpose: String,
    coin_type: String,
    account: String,
    change: String,
    index: String,
}
async fn get_address(
    Path(GetAddressParams {
        key_scheme, purpose, coin_type, account, change, index
    }): Path<GetAddressParams>,
    State(wallet): State<Arc<Wallet>>
) -> Result<impl IntoResponse, StatusCode> {
    let derivation_path = format!("m/{}/{}/{}/{}/{}", purpose, coin_type, account, change, index);
    let sig_scheme = SignatureScheme::from_str(key_scheme.as_str()).unwrap();
    let addr = wallet.create_address(&sig_scheme, Some(derivation_path.clone())).unwrap();
    Ok(Json(CreateAddressResponse { 
        derivation_path: derivation_path.clone(),
        address: addr.to_string()
     }))
}

async fn create_address(
    State(wallet): State<Arc<Wallet>>,
    Form(req): Form<CreateAddressRequest>) -> Result<impl IntoResponse, StatusCode> {
    let key_scheme = SignatureScheme::from_str(req.key_scheme.as_str()).unwrap();
    let addr = wallet.create_address(&key_scheme, req.derivation_path.clone()).unwrap();
    Ok(Json(CreateAddressResponse { 
        derivation_path: req.derivation_path.clone().unwrap_or("".to_owned()),
        address: addr.to_string()
     }))
}

// signature
#[derive(Deserialize)]
struct SignRequest {
    key_scheme: String,
    derivation_path: Option<String>,
    data: String,
}

#[derive(Deserialize, Serialize)]
struct SignResponse {
    signature: String
}

async fn make_signature(
    State(wallet): State<Arc<Wallet>>,
    Form(req): Form<SignRequest>) -> Result<impl IntoResponse, StatusCode> {

    let decoded = Base64::decode(req.data.as_str()).or_else(|_| Err(StatusCode::BAD_REQUEST))?;
    let key_scheme = SignatureScheme::from_str(req.key_scheme.as_str()).unwrap();
    let sig = wallet.sign(&key_scheme, req.derivation_path, decoded.as_slice()).unwrap();
    Ok(Json(SignResponse { 
        signature: sig.signature(),
    }))
}