mod handlers;
mod types;
use crate::handlers::*;
use crate::types::*;

use clap::Parser;
use concordium_rust_sdk::common::types::KeyPair;
use concordium_rust_sdk::{
    common::{self as crypto_common},
    id::{
        constants::{ArCurve, AttributeKind},
        id_proof_types::Statement,
    },
    v2::BlockIdentifier,
};
use log::info;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use warp::Filter;

/// Structure used to receive the correct command line arguments.
#[derive(clap::Parser, Debug)]
#[clap(arg_required_else_help(true))]
#[clap(version, author)]
struct IdVerifierConfig {
    #[clap(
        long = "node",
        help = "GRPC V2 interface of the node.",
        default_value = "http://localhost:20000"
    )]
    endpoint: concordium_rust_sdk::v2::Endpoint,
    #[clap(
        long = "port",
        default_value = "8100",
        help = "Port on which the server will listen on."
    )]
    port: u16,
    #[structopt(
        long = "log-level",
        default_value = "debug",
        help = "Maximum log level."
    )]
    log_level: log::LevelFilter,
    #[clap(
        long = "statement",
        help = "The statement that the server accepts proofs for."
    )]
    statement: String,
    #[structopt(
        long = "sign-key",
        help = "Sign key of the first credential of the signer"
    )]
    sign_key: String,
    #[structopt(
        long = "verify-key",
        help = "Verify key of the first credential of the signer"
    )]
    verify_key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = IdVerifierConfig::parse();
    let mut log_builder = env_logger::Builder::new();
    // only log the current module (main).
    log_builder.filter_level(app.log_level); // filter filter_module(module_path!(), app.log_level);
    log_builder.init();
    let statement: Statement<ArCurve, AttributeKind> = serde_json::from_str(&app.statement)?;

    let mut client = concordium_rust_sdk::v2::Client::new(app.endpoint).await?;
    let global_context = client
        .get_cryptographic_parameters(BlockIdentifier::LastFinal)
        .await?
        .response;

    log::debug!("Acquired data from the node.");

    let state = Server {
        challenges: Arc::new(Mutex::new(HashMap::new())),
        global_context: Arc::new(global_context),
    };
    let prove_state = state.clone();
    let challenge_state = state.clone();

    let cors = warp::cors()
        .allow_any_origin()
        .allow_header("Content-Type")
        .allow_method("POST");

    // 1a. get challenge
    let get_challenge = warp::get()
        .and(warp::path!("api" / "challenge"))
        .and(warp::query::<WithAccountAddress>())
        .and_then(move |query: WithAccountAddress| {
            handle_get_challenge(challenge_state.clone(), query.address)
        });

    // 1b. get statement
    // change it to check older than 18 only.
    let get_statement = warp::get()
        .and(warp::path!("api" / "statement"))
        .map(move || warp::reply::json(&app.statement));

    // 2. Provide proof
    let provide_proof = warp::post()
        .and(warp::filters::body::content_length_limit(50 * 1024))
        .and(warp::path!("api" / "prove"))
        .and(warp::body::json())
        .and_then(move |request: ChallengedProof| {
            let kp = KeyPair::from(ed25519_dalek::Keypair {
                public: ed25519_dalek::PublicKey::from_bytes(
                    hex::decode(&app.verify_key).unwrap().as_slice(),
                )
                .unwrap(),
                secret: ed25519_dalek::SecretKey::from_bytes(
                    hex::decode(&app.sign_key).unwrap().as_slice(),
                )
                .unwrap(),
            });
            handle_provide_proof(
                client.clone(),
                prove_state.clone(),
                statement.clone(),
                request,
                kp,
            )
        });

    info!(
        "Starting up HTTP serve
r. Listening on port {}.",
        app.port
    );

    tokio::spawn(handle_clean_state(state.clone()));

    let server = get_challenge
        .or(get_statement)
        .or(provide_proof)
        .recover(handle_rejection)
        .with(cors)
        .with(warp::trace::request());
    warp::serve(server).run(([0, 0, 0, 0], app.port)).await;
    Ok(())
}