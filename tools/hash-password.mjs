#!/usr/bin/env node
/**
 * Vortexis demo hesabı için PBKDF2-SHA256 parola özeti üretir.
 *
 * Kullanım:
 *   node tools/hash-password.mjs "yeni-parola"
 *
 * Çıktıdaki salt, hash ve iterations değerlerini assets/js/config.js
 * içindeki demoAccount alanına yazın. Parolayı hiçbir zaman depoya
 * veya siteye düz metin olarak eklemeyin.
 */
import { randomBytes, pbkdf2Sync } from "node:crypto";

const password = process.argv[2];
const iterations = Number(process.argv[3] || 120000);

if (!password) {
  console.error('Kullanım: node tools/hash-password.mjs "yeni-parola" [iterations]');
  process.exit(1);
}

if (!Number.isInteger(iterations) || iterations < 100000) {
  console.error("iterations en az 100000 olan bir tam sayı olmalıdır.");
  process.exit(1);
}

const salt = randomBytes(16);
const hash = pbkdf2Sync(password, salt, iterations, 32, "sha256");

console.log("");
console.log("demoAccount: {");
console.log(`  email: "vortexisecure@gmail.com",`);
console.log(`  name: "Vortexis Demo",`);
console.log(`  salt: "${salt.toString("base64")}",`);
console.log(`  hash: "${hash.toString("base64")}",`);
console.log(`  iterations: ${iterations}`);
console.log("}");
console.log("");
console.log("Not: Parolayı bu çıktıyla birlikte paylaşmayın. Yalnızca salt/hash değerlerini config.js dosyasına ekleyin.");
