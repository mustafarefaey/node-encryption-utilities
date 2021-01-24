const crypto = require("crypto");

/**
 * @returns {crypto.ECDH}
 */
function generateKeysPair() {
  const instance = crypto.createECDH("secp256k1");
  instance.generateKeys();
  return instance;
}

/**
 * @param {String} key
 * @param {String} cleartext
 *
 * @returns {String} encrypted text base64 encoded
 */
function encrypt(key, cleartext) {
  if (typeof key !== "string" || !key) {
    throw new TypeError('Provided "key" must be a non-empty string');
  }

  if (typeof cleartext !== "string" || !cleartext) {
    throw new TypeError('Provided "cleartext" must be a non-empty string');
  }

  const hash = crypto.createHash("sha256");
  hash.update(key);

  // Initialization Vector
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", hash.digest(), iv);

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(cleartext), "utf8"),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  const encryptedText = Buffer.concat([iv, authTag, ciphertext]).toString(
    "base64"
  );

  return encryptedText;
}

/**
 * @param {String} key
 * @param {String} encryptedText base64 encoded
 *
 * @returns {String} clear text
 */
function decrypt(key, encryptedText) {
  if (typeof key !== "string" || !key) {
    throw new TypeError('Provided "key" must be a non-empty string');
  }

  if (typeof encryptedText !== "string" || !encryptedText) {
    throw new TypeError('Provided "encryptedText" must be a non-empty string');
  }

  const encryptedBuffer = Buffer.from(encryptedText, "base64");

  const hash = crypto.createHash("sha256");
  hash.update(key);

  if (encryptedBuffer.length < 17) {
    throw new TypeError(
      'Provided "encryptedText" must decrypt to a non-empty string'
    );
  }

  // Initialization Vector
  const iv = encryptedBuffer.slice(0, 16);
  const authTag = encryptedBuffer.slice(16, 32);
  const decipher = crypto.createDecipheriv("aes-256-gcm", hash.digest(), iv);
  decipher.setAuthTag(authTag);
  const cipherText = decipher.update(
    encryptedBuffer.slice(32),
    "base64",
    "utf-8"
  );

  const clearText = cipherText + decipher.final("utf-8");

  return clearText;
}

module.exports = {
  generateKeysPair,
  encrypt,
  decrypt,
};
