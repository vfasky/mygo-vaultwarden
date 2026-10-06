// SPDX-License-Identifier: GPL-3.0-only
// Run: "${WAKU_BUN_EXECUTABLE:-bun}" scripts/generate-icons.ts
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const scratch = await mkdtemp(join(tmpdir(), "vaultwarden-icons-"));
const master = join(root, "resources/branding/vaultwarden-master.png");
const icon = join(root, "resources/icon.png");
const icns = join(root, "macos/App/AppIcon.icns");

async function run(command: string[]) {
  const result = await Bun.spawn(command, { stdout: "inherit", stderr: "inherit" }).exited;
  if (result !== 0) throw new Error(`${command[0]} exited with ${result}`);
}

try {
  const metadata = await new Bun.Image(master).metadata();
  if (metadata.width !== metadata.height || metadata.width < 1024) {
    throw new Error("Master artwork must be square and at least 1024px.");
  }
  const normalized = join(scratch, "master-1024.png");
  await new Bun.Image(master).resize(1024, 1024).png().write(normalized);
  await run(["swift", join(root, "scripts/mask-app-icon.swift"), normalized, icon]);
  const iconset = join(scratch, "AppIcon.iconset");
  await mkdir(iconset);
  for (const points of [16, 32, 128, 256, 512]) {
    for (const scale of [1, 2]) {
      const pixels = points * scale;
      const name = `icon_${points}x${points}${scale === 2 ? "@2x" : ""}.png`;
      await new Bun.Image(icon).resize(pixels, pixels).png().write(join(iconset, name));
    }
  }
  await run(["iconutil", "--convert", "icns", "--output", icns, iconset]);
  console.log(`Generated ${icon}\nGenerated ${icns}`);
} finally {
  await rm(scratch, { recursive: true, force: true });
}
