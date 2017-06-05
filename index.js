const sodium = require('libsodium-wrappers');

var encryptedString = "dlsKgrbN832H1i5XqlB_HX7jYmR7QHc-IvbD-6HFMJdLH3c-ZLzkOqIu9ZqHNwyiFhm496AlRb1OAeCVYCFXhRH95DVCkjvFEk2NnoDNqft9uIYC0QfmpfctDsPxhoahti6hthkiW-B_z5R4mAZAupkkLZwM5hv4NOfgDPNzM_swm-8=";

var privateKey = Buffer.from("gWHZE3Asozs8virRpdqrzY68WkRz1mlJrIm9k0-iR_M=", 'base64')
var peerPublicKey = Buffer.from("LF-s5obfbHD-u37zxIXAi_L4w9jW8zIGv9wq2qA2RyY=", 'base64')

var decrypt = function(buf) {
  if (buf.length <= 24) {
    throw new Error("buffer is too short");
  }
  var nonce = buf.slice(0, sodium.crypto_box_NONCEBYTES);
  var encryptedMessage = buf.slice(sodium.crypto_box_NONCEBYTES);
  var msg = sodium.crypto_box_open_easy(encryptedMessage, nonce, peerPublicKey, privateKey, 'text');
  return msg;
}

var encrypted = Buffer.from(encryptedString, 'base64')
console.log(decrypt(encrypted));
