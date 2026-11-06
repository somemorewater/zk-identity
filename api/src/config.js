export const config = {
  port: Number(process.env.PORT ?? 3000),
  databaseUrl: process.env.DATABASE_URL ?? 'postgres://zk:zk@localhost:5438/zk',
  // Required: admin endpoints are disabled when empty.
  adminKey: process.env.ADMIN_API_KEY ?? '',
  verifierBin: process.env.VERIFIER_BIN ?? '../target/release/zk-verifier',
  vkPath: process.env.VK_PATH ?? '../keys/vk.bin',
  challengeTtlSeconds: Number(process.env.CHALLENGE_TTL_SECONDS ?? 300),
  minAgeYears: 18,
};
