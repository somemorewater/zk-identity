// Speaks the same stdio protocol as the Rust zk-verifier, for client tests.
import { createInterface } from 'node:readline';
console.log(JSON.stringify({ ready: true }));
createInterface({ input: process.stdin }).on('line', (line) => {
  const req = JSON.parse(line);
  if (req.proof === 'crash') process.exit(1);
  if (req.proof === 'hang') return;
  const valid = req.proof === 'good' && req.public_inputs.length === 5;
  console.log(JSON.stringify(valid ? { id: req.id, valid } : { id: req.id, valid, error: 'nope' }));
});
