#!/usr/bin/env node
const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const nativeDir = path.join(__dirname, "..", "native");
const binaries = ["veil", "veilkey", "veilkey-cli", "veilkey-session-config"];

// Check if native binaries exist (pre-built)
const allExist = binaries.every(b => fs.existsSync(path.join(nativeDir, b)));

if (allExist) {
  // Make executable + codesign for macOS
  for (const b of binaries) {
    const binPath = path.join(nativeDir, b);
    fs.chmodSync(binPath, 0o755);
    if (process.platform === "darwin") {
      try {
        execSync(`codesign --force --sign - "${binPath}" 2>/dev/null`, { stdio: "ignore" });
      } catch (_) {}
    }
  }
  console.log("[veilkey] Native binaries ready.");
} else {
  // Build from source (requires Rust)
  console.log("[veilkey] Native binaries not found, building from source...");
  try {
    // Find repo root (walk up from node_modules)
    let dir = __dirname;
    while (dir !== "/" && !fs.existsSync(path.join(dir, "Cargo.toml"))) {
      dir = path.dirname(dir);
    }
    if (!fs.existsSync(path.join(dir, "Cargo.toml"))) {
      console.error("[veilkey] Cannot find Cargo.toml. Install Rust and build manually.");
      process.exit(0); // Don't fail npm install
    }
    execSync("cargo build --release -p veil-cli-rs", { cwd: dir, stdio: "inherit" });
    const releaseDir = path.join(dir, "target", "release");
    fs.mkdirSync(nativeDir, { recursive: true });
    for (const b of binaries) {
      const src = path.join(releaseDir, b);
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, path.join(nativeDir, b));
        fs.chmodSync(path.join(nativeDir, b), 0o755);
      }
    }
    console.log("[veilkey] Built and installed native binaries.");
  } catch (e) {
    console.error("[veilkey] Build failed:", e.message);
    console.error("[veilkey] Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
    process.exit(0);
  }
}
