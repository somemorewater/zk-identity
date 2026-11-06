//! Issuer + holder tooling.
//!
//!   zk-cli setup  --out keys
//!   zk-cli issue  --state issuer.json --dob 2000-05-17 --out cred.json
//!   zk-cli root   --state issuer.json
//!   zk-cli prove  --state issuer.json --cred cred.json --pk keys/pk.bin \
//!                 --verifier-id <hex> --challenge <hex> --cutoff-days <n> --out proof.json
//!   zk-cli verify --vk keys/vk.bin --proof proof.json
//!   zk-cli cutoff

use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{Datelike, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use zk_circuits::{
    build_circuit, fr_from_hex, fr_to_hex, from_bytes, merkle, prepare_vk, prove, random_fr, setup, to_bytes,
    verify, Fr, MerkleTree, Proof, ProvingKey, PublicInputs, VerifyingKey,
};

#[derive(Parser)]
#[command(name = "zk-cli", about = "ZK age-credential issuer and holder tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// DEV-ONLY trusted setup: writes pk.bin and vk.bin.
    Setup {
        #[arg(long, default_value = "keys")]
        out: PathBuf,
    },
    /// Issue a credential: adds a leaf to the issuer tree and writes the holder's credential file.
    Issue {
        #[arg(long)]
        state: PathBuf,
        /// Date of birth, YYYY-MM-DD
        #[arg(long)]
        dob: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the issuer tree's current root (64-char hex).
    Root {
        #[arg(long)]
        state: PathBuf,
    },
    /// Generate a proof for a verifier challenge.
    Prove {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        cred: PathBuf,
        #[arg(long)]
        pk: PathBuf,
        #[arg(long)]
        verifier_id: String,
        #[arg(long)]
        challenge: String,
        #[arg(long)]
        cutoff_days: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a proof file locally.
    Verify {
        #[arg(long)]
        vk: PathBuf,
        #[arg(long)]
        proof: PathBuf,
    },
    /// Print today's 18-year cutoff in days since 1900-01-01 (convenience for local testing).
    Cutoff,
}

#[derive(Serialize, Deserialize, Default)]
struct IssuerState {
    leaves: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Credential {
    secret: String,
    dob_days: u32,
    index: usize,
}

#[derive(Serialize, Deserialize)]
struct ProofFile {
    proof: String,
    nullifier: String,
    merkle_root: String,
    cutoff_days: u32,
    verifier_id: String,
    challenge: String,
}

fn epoch() -> NaiveDate {
    NaiveDate::from_ymd_opt(1900, 1, 1).unwrap()
}

fn days_since_1900(d: NaiveDate) -> Result<u32> {
    let n = (d - epoch()).num_days();
    u32::try_from(n).map_err(|_| anyhow::anyhow!("date {d} is before 1900-01-01"))
}

fn load_tree(path: &PathBuf) -> Result<MerkleTree> {
    let state: IssuerState = if path.exists() {
        serde_json::from_slice(&fs::read(path)?).context("parsing issuer state")?
    } else {
        IssuerState::default()
    };
    let leaves = state.leaves.iter().map(|h| fr_from_hex(h)).collect::<Result<Vec<_>>>()?;
    Ok(MerkleTree { leaves })
}

fn save_tree(path: &PathBuf, tree: &MerkleTree) -> Result<()> {
    let state = IssuerState { leaves: tree.leaves.iter().map(fr_to_hex).collect() };
    fs::write(path, serde_json::to_vec_pretty(&state)?)?;
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Setup { out } => {
            fs::create_dir_all(&out)?;
            eprintln!("running trusted setup (dev only)...");
            let (pk, vk) = setup()?;
            fs::write(out.join("pk.bin"), to_bytes(&pk))?;
            fs::write(out.join("vk.bin"), to_bytes(&vk))?;
            eprintln!("wrote {}/pk.bin and {}/vk.bin", out.display(), out.display());
        }

        Cmd::Issue { state, dob, out } => {
            let date = NaiveDate::parse_from_str(&dob, "%Y-%m-%d").context("dob must be YYYY-MM-DD")?;
            let dob_days = days_since_1900(date)?;
            let mut tree = load_tree(&state)?;
            let secret = random_fr();
            let leaf = merkle::leaf(secret, Fr::from(dob_days as u64));
            let index = tree.leaves.len();
            tree.leaves.push(leaf);
            save_tree(&state, &tree)?;
            let cred = Credential { secret: fr_to_hex(&secret), dob_days, index };
            fs::write(&out, serde_json::to_vec_pretty(&cred)?)?;
            println!("{}", fr_to_hex(&tree.root()));
            eprintln!("issued credential #{index}; publish the printed root to the verification service");
        }

        Cmd::Root { state } => {
            println!("{}", fr_to_hex(&load_tree(&state)?.root()));
        }

        Cmd::Prove { state, cred, pk, verifier_id, challenge, cutoff_days, out } => {
            let tree = load_tree(&state)?;
            let cred: Credential = serde_json::from_slice(&fs::read(&cred)?)?;
            if cred.dob_days > cutoff_days {
                bail!("credential does not satisfy the claim (holder is too young); refusing to prove");
            }
            let pk: ProvingKey<_> = from_bytes(&fs::read(&pk)?)?;
            let (circuit, public) = build_circuit(
                &tree,
                cred.index,
                fr_from_hex(&cred.secret)?,
                Fr::from(cred.dob_days as u64),
                cutoff_days,
                fr_from_hex(&verifier_id)?,
                fr_from_hex(&challenge)?,
            )?;
            let proof = prove(&pk, circuit)?;
            let file = ProofFile {
                proof: hex::encode(to_bytes(&proof)),
                nullifier: fr_to_hex(&public.nullifier),
                merkle_root: fr_to_hex(&public.merkle_root),
                cutoff_days,
                verifier_id,
                challenge,
            };
            fs::write(&out, serde_json::to_vec_pretty(&file)?)?;
            eprintln!("wrote {}", out.display());
        }

        Cmd::Verify { vk, proof } => {
            let vk: VerifyingKey<_> = from_bytes(&fs::read(&vk)?)?;
            let pf: ProofFile = serde_json::from_slice(&fs::read(&proof)?)?;
            let proof: Proof<_> = from_bytes(&hex::decode(&pf.proof)?)?;
            let public = PublicInputs {
                merkle_root: fr_from_hex(&pf.merkle_root)?,
                cutoff_days: Fr::from(pf.cutoff_days as u64),
                verifier_id: fr_from_hex(&pf.verifier_id)?,
                challenge: fr_from_hex(&pf.challenge)?,
                nullifier: fr_from_hex(&pf.nullifier)?,
            };
            let ok = verify(&prepare_vk(&vk), &public, &proof)?;
            println!("{}", if ok { "VALID" } else { "INVALID" });
            if !ok {
                std::process::exit(1);
            }
        }

        Cmd::Cutoff => {
            let today = Utc::now().date_naive();
            let y = today.year() - 18;
            let d = today
                .with_year(y)
                .or_else(|| NaiveDate::from_ymd_opt(y, 2, 28))
                .context("computing cutoff")?;
            println!("{}", days_since_1900(d)?);
        }
    }
    Ok(())
}
