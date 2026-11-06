.RECIPEPREFIX = >
.PHONY: build setup db migrate api test demo

export DATABASE_URL ?= postgres://zk:zk@localhost:5438/zk
export ADMIN_API_KEY ?= dev-admin-key

build:
> cargo build --release

# DEV-ONLY trusted setup; writes keys/pk.bin and keys/vk.bin
setup: build
> ./target/release/zk-cli setup --out keys

db:
> docker compose up -d --wait db

migrate:
> cd api && npm install && npm run migrate

api:
> cd api && npm start

test:
> cargo test --release
> cd api && npm test

demo:
> bash scripts/demo.sh
