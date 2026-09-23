/**
 * Real-process boot probe for the M4 restart integration test.
 * Compiled to dist/ by `npm run build`; spawned as a separate OS
 * process twice to prove epoch + safe-state behavior across a genuine
 * process boundary (not an in-memory simulation).
 *
 * Usage: node dist/tests/m4-probe.js boot <stateDir>
 * Always prints one JSON line on stdout; transport failures surface
 * as non-zero exit / no output.
 */
import { boot } from "../src/bootstrap/boot.js";

function main(): void {
  const [cmd, stateDir] = process.argv.slice(2);
  if (cmd !== "boot" || typeof stateDir !== "string") {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: "usage" })}\n`);
    return;
  }
  const result = boot(stateDir);
  if (!result.ok) {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: result.reason })}\n`);
    return;
  }
  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      epoch: result.session.epoch,
      sleep: result.session.sleep,
      killEngaged: result.session.killSwitch.engaged,
      grants: result.session.grants.length,
    })}\n`,
  );
}

main();
