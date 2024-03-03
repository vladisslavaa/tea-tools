const crypto = require('crypto');

// Generate a random AES key
const aesKey = crypto.randomBytes(32);

// Encrypt and decrypt a message using AES
const message = 'Hello, world!';
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
let encryptedMessage = cipher.update(message, 'utf8', 'hex');
encryptedMessage += cipher.final('hex');

const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf8');
decryptedMessage += decipher.final('utf8');

console.log('Original Message:', message);
console.log('Encrypted Message:', encryptedMessage);
console.log('Decrypted Message:', decryptedMessage);

// Sign and verify the integrity of the message using HMAC
const hmacKey = crypto.randomBytes(32);
const hmac = crypto.createHmac('sha256', hmacKey);
hmac.update(message);
const signature = hmac.digest('hex');

const isValid = crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(hmac.digest('hex'), 'hex'));

console.log('Signature:', signature);
console.log('Is Message Valid?', isValid);
