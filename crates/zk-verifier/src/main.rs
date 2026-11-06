//! Long-running verifier sidecar. Speaks line-delimited JSON on stdin/stdout.
//!
//!   -> {"id":"1","proof":"<hex>","public_inputs":["<64hex>" x5]}
//!   <- {"id":"1","valid":true}
//!   <- {"id":"1","valid":false,"error":"..."}
//!
//! First line emitted is {"ready":true} once the verifying key is loaded.
//! Public input order: merkle_root, cutoff_days, verifier_id, challenge, nullifier.

use std::{
    env, fs,
    io::{self, BufRead, Write},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zk_circuits::{fr_from_hex, from_bytes, prepare_vk, verify, PreparedVerifyingKey, Proof, PublicInputs, VerifyingKey};

#[derive(Deserialize)]
struct Request {
    id: String,
    proof: String,
    public_inputs: Vec<String>,
}

#[derive(Serialize)]
struct Response {
    id: Option<String>,
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn check(pvk: &PreparedVerifyingKey<zk_circuits::Bn254>, req: &Request) -> Result<bool> {
    if req.public_inputs.len() != 5 {
        bail!("expected 5 public inputs, got {}", req.public_inputs.len());
    }
    let f = |i: usize| fr_from_hex(&req.public_inputs[i]);
    let inputs = PublicInputs {
        merkle_root: f(0)?,
        cutoff_days: f(1)?,
        verifier_id: f(2)?,
        challenge: f(3)?,
        nullifier: f(4)?,
    };
    let proof: Proof<_> = from_bytes(&hex::decode(&req.proof).context("proof is not hex")?)?;
    verify(pvk, &inputs, &proof)
}

fn main() -> Result<()> {
    let vk_path = env::args().nth(1).context("usage: zk-verifier <vk.bin>")?;
    let vk: VerifyingKey<_> = from_bytes(&fs::read(&vk_path).with_context(|| format!("reading {vk_path}"))?)?;
    let pvk = prepare_vk(&vk);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{{\"ready\":true}}")?;
    out.flush()?;

    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Err(e) => Response { id: None, valid: false, error: Some(format!("bad request: {e}")) },
            Ok(req) => match check(&pvk, &req) {
                Ok(valid) => Response { id: Some(req.id), valid, error: None },
                Err(e) => Response { id: Some(req.id), valid: false, error: Some(e.to_string()) },
            },
        };
        writeln!(out, "{}", serde_json::to_string(&resp)?)?;
        out.flush()?;
    }
    Ok(())
}
