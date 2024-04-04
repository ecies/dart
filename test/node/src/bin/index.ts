#!/usr/bin/env node

import { encrypt, decrypt } from 'eciesjs';

const args = process.argv.slice(2);
const encryptMode = args[0] === 'encrypt';
if (encryptMode) {
  const publicKey = args[1];
  const message = args[2];

  const publicKeyBytes = Buffer.from(publicKey!, 'base64');
  const messageBytes = Buffer.from(message!, 'base64');
  const encrypted = encrypt(publicKeyBytes, messageBytes);
  process.stdout.write(encrypted.toString('base64'));
} else {
  const privateKey = args[1];
  const enciphered = args[2];

  const privateKeyBytes = Buffer.from(privateKey!, 'base64');
  const messageBytes = Buffer.from(enciphered!, 'base64');
  process.stdout.write(decrypt(privateKeyBytes, messageBytes).toString('base64'));
}
