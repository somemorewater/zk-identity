#!/usr/bin/env bash
# End-to-end demo. Prereqs: `make setup db migrate`, and `make api` running in another terminal.
set -euo pipefail
cd "$(dirname "$0")/.."

API=${API:-http://localhost:3000}
ADMIN=${ADMIN_API_KEY:-dev-admin-key}
CLI=./target/release/zk-cli
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
jget() {
  node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s)[process.argv[1]]))' "$1"
}
post() { # path json [curl args...]
  local path=$1 body=$2; shift 2
  curl -sS -X POST "$API$path" -H 'content-type: application/json' "$@" -d "$body"
}
publish_root() { post "/v1/admin/issuers/$ISSUER/roots" "{\"root\":\"$1\"}" -H "x-admin-key: $ADMIN" > /dev/null; }
new_challenge() { post /v1/challenges "{\"claim_type\":\"age_gte_18\",\"issuer_id\":\"$ISSUER\"}" -H "x-api-key: $VKEY"; }
prove_with() { # <credential file> <challenge json>
  $CLI prove --state "$W/issuer.json" --cred "$1" --pk keys/pk.bin \
    --verifier-id "$(echo "$2" | jget verifier_id)" --challenge "$(echo "$2" | jget challenge)" \
    --cutoff-days "$(echo "$2" | jget cutoff_days)" --out "$W/proof.json"
}
submit() { # <challenge_id>
  local body
  body=$(node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1]));
    console.log(JSON.stringify({challenge_id:process.argv[2],proof:p.proof,nullifier:p.nullifier}))' "$W/proof.json" "$1")
  curl -sS -X POST "$API/v1/verify" -H 'content-type: application/json' -H "x-api-key: $VKEY" \
    -w '  [HTTP %{http_code}]\n' -d "$body"
}

step "1. Admin creates an issuer and a verifier (a shop)"
ISSUER=$(post /v1/admin/issuers '{"name":"demo-issuer"}' -H "x-admin-key: $ADMIN" | jget id)
VJSON=$(post /v1/admin/verifiers '{"name":"demo-shop"}' -H "x-admin-key: $ADMIN")
VKEY=$(echo "$VJSON" | jget api_key)
echo "issuer=$ISSUER"

step "2. Issuer issues a credential (born 2000-05-17) and publishes its tree root"
ROOT=$($CLI issue --state "$W/issuer.json" --dob 2000-05-17 --out "$W/adult.json")
publish_root "$ROOT"; echo "root=$ROOT"

step "3. Shop requests a challenge; holder proves 'over 18' without revealing the birth date"
CH=$(new_challenge); CID=$(echo "$CH" | jget challenge_id)
prove_with "$W/adult.json" "$CH"
submit "$CID"

step "4. Replaying the same proof/challenge is rejected"
submit "$CID"

step "5. Fresh challenge, same credential: valid, and the shop learns already_seen=true (no identity)"
CH=$(new_challenge); CID=$(echo "$CH" | jget challenge_id)
prove_with "$W/adult.json" "$CH"
submit "$CID"

step "6. A minor's credential cannot produce a proof"
$CLI issue --state "$W/issuer.json" --dob 2015-01-01 --out "$W/minor.json" > "$W/root2"
publish_root "$(cat "$W/root2")"
CH=$(new_challenge)
prove_with "$W/minor.json" "$CH" || echo "(holder tool refused: credential does not satisfy the claim)"

step "7. Revocation: issuer publishes a root that omits the adult's leaf"
$CLI issue --state "$W/other.json" --dob 1990-01-01 --out "$W/other-cred.json" > "$W/root3"
publish_root "$(cat "$W/root3")"
CH=$(new_challenge); CID=$(echo "$CH" | jget challenge_id)
prove_with "$W/adult.json" "$CH"   # holder still proves against the old tree...
submit "$CID"                      # ...but the service verifies against the current root

echo; echo "demo complete"
