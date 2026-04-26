#!/usr/bin/env node
const crypto = require('crypto');

function base64Encode(buffer) {
  return buffer.toString('base64');
}

function base64Decode(data) {
  return Buffer.from(data, 'base64');
}

function hash(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256').toString('hex');
}

function derive(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256').toString('base64');
}

function encrypt(plaintext, keyB64) {
  const key = base64Decode(keyB64);
  if (key.length !== 32) {
    throw new Error('invalid key length');
  }
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return base64Encode(Buffer.concat([iv, encrypted]));
}

function decrypt(ciphertextB64, keyB64) {
  const key = base64Decode(keyB64);
  if (key.length !== 32) {
    throw new Error('invalid key length');
  }
  const ciphertext = base64Decode(ciphertextB64);
  if (ciphertext.length < 16) {
    throw new Error('invalid ciphertext');
  }
  const iv = ciphertext.slice(0, 16);
  const encrypted = ciphertext.slice(16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function generate(length = 12) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{};:,.<>/?\\|';
  const bytes = crypto.randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i += 1) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
}

function strength(password) {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return score;
}

function usage() {
  console.log('Usage: module3 <command> [args...]');
  console.log('Commands:');
  console.log('  hash <password> <salt>');
  console.log('  derive <password> <salt>');
  console.log('  encrypt <plaintext> <base64key>');
  console.log('  decrypt <ciphertext> <base64key>');
  console.log('  generate [length]');
  console.log('  strength <password>');
}

const [,, command, arg1, arg2] = process.argv;

if (!command) {
  usage();
  process.exit(1);
}

try {
  switch (command) {
    case 'hash':
      if (!arg1 || !arg2) throw new Error('hash requires password and salt');
      console.log(hash(arg1, arg2));
      break;
    case 'derive':
      if (!arg1 || !arg2) throw new Error('derive requires password and salt');
      console.log(derive(arg1, arg2));
      break;
    case 'encrypt':
      if (!arg1 || !arg2) throw new Error('encrypt requires plaintext and base64key');
      console.log(encrypt(arg1, arg2));
      break;
    case 'decrypt':
      if (!arg1 || !arg2) throw new Error('decrypt requires ciphertext and base64key');
      console.log(decrypt(arg1, arg2));
      break;
    case 'generate':
      console.log(generate(arg1 ? Number(arg1) : 12));
      break;
    case 'strength':
      if (!arg1) throw new Error('strength requires a password');
      console.log(strength(arg1));
      break;
    default:
      usage();
      process.exit(1);
  }
} catch (err) {
  console.error('ERROR:', err.message);
  process.exit(1);
}
