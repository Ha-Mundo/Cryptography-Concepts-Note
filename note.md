# 1. Hash

## The word hash actually has **culinary roots**. It means to **chop and mix** and that perfectly describes what a hashing function does. It takes an input value of any length and outputs a fixed length value. Hashing algorithms, like SHA (Secure Hashing Algorithm), produce a random, unique, fixed-length string from a given input. They are often used to compare two values, like passwords, for equality.

- The same input will always produce the same output.
- Fast to compute, but computationally expensive to find the original input
- Small probability of collision (unique)

## **Create a Hash in Node.js**

### Create a hash using the crypto module, then use it to compare two values.

```js
const { createHash } = require("crypto");

// Create a string hash

function hash(str) {
  return createHash("sha256").update(str).digest("hex");
}

// Compare two hashed passwords

let password = "hi-mom!";
const hash1 = hash(password);
console.log(hash1);

/// ... some time later

password = "hi-mom";
const hash2 = hash(password);
const match = hash1 === hash2;

console.log(match ? "✔️  good password" : "❌  password does not match");
```

# 2. Salt

## Hashes are great for making passwords unreadable, but because they always produce the same output, they are not very secure. A salt is a random string that is added to the input before hashing. This makes the hash more unique and harder to guess.

## Users often to use weak passwords, like “password123”. When a database is compromised, the attacker can easily find the value of an unsalted hash by searching precomputed **rainbow table** of common hashes - salting fixes this.

- Used to make a hash harder to guess
- Appends a random string to the input before hashing

## **Password Salt with Scrypt in Node.js**

### Below is an example of a password salt using the **scrypt** algorithm in Node crypto.

```js
const { scryptSync, randomBytes, timingSafeEqual } = require("crypto");

function signup(email, password) {
  const salt = randomBytes(16).toString("hex");
  const hashedPassword = scryptSync(password, salt, 64).toString("hex");

  const user = { email, password: `${salt}:${hashedPassword}` };

  users.push(user);

  return user;
}

function login(email, password) {
  const user = users.find(v => v.email === email);

  const [salt, key] = user.password.split(":");
  const hashedBuffer = scryptSync(password, salt, 64);

  const keyBuffer = Buffer.from(key, "hex");
  const match = timingSafeEqual(hashedBuffer, keyBuffer);

  if (match) {
    return "login success!";
  } else {
    return "login fail!";
  }
}

const users = [];

const user = signup("foo@bar.com", "pa$$word");

console.log(user);

const result = login("foo@bar.com", "password");

console.log(result);
```

# 3. HMAC

## HMAC is a keyed hash of data - like a hash with a password. To create a HMAC you need to have the key, therefore allowing you to verify both the authenticity and originator of the data. Using a different key produces a different output.

- Think of HMAC as a hash with a password or key
- Only someone with the key can create an authentic hash

## **HMAC in Node.js**

```js
const { createHmac } = require("crypto");

const password = "super-secret!";
const message = "🎃 hello jack";

const hmac = createHmac("sha256", password).update(message).digest("hex");

console.log(hmac);
```

# 4. Symmetric Encryption

## Encryption is the process making a message confidential (like a hash), while allowing it to be reversable (decrypted) with the proper key. Each time a message is encrypted it is randomized to produce a different output. In **symmetric encryption**, the same key is used to encrypt and decrypt the message.

- The same input will produce a different output, unlike hashes
- Encrypted message can be reversed with the key
- Same key used to encrypt and decrypt message

## **Symmetric Encryption in Node.js**

### Perform symmetric encryption in Node by creating a cipher. Encryption also has an initialization vector (IV) to randomize the pattern so a sequence of text won’t produce the same output as a previous sequence.

```js
const { createCipheriv, randomBytes, createDecipheriv } = require("crypto");

/// Cipher

const message = "i like turtles";
const key = randomBytes(32);
const iv = randomBytes(16);

const cipher = createCipheriv("aes256", key, iv);

/// Encrypt

const encryptedMessage =
  cipher.update(message, "utf8", "hex") + cipher.final("hex");
console.log(`Encrypted: ${encryptedMessage}`);

/// Decrypt

const decipher = createDecipheriv("aes256", key, iv);
const decryptedMessage =
  decipher.update(encryptedMessage, "hex", "utf-8") + decipher.final("utf8");
console.log(`Deciphered: ${decryptedMessage.toString("utf-8")}`);
```

# 5. Keypairs

## Using a shared key works for encryption works, but the problem is that both parties must agree upon the key. This is problematic in the real world because it’s not practical or secure to share across a network. The solution is to use an algoritm like RSA that generates a keypair containing a public and private key. As their names indicate, the private key should be kept secret, while the public key can be shared freely.

## **Generate an RSA Keypair in Node.js**

```js
const { generateKeyPairSync } = require("crypto");

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048, // the length of your key in bits
  publicKeyEncoding: {
    type: "spki", // recommended to be 'spki' by the Node.js docs
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8", // recommended to be 'pkcs8' by the Node.js docs
    format: "pem",
  },
});

console.log(publicKey);
console.log(privateKey);
```

# 6. Asymmetric Encryption

## Asymmetric encryption depends on two keys. Encrypt a message with the public key and decrypt it with the private key.

## Asymmetric encryption is used on the web whenever you use HTTPS to establish an encrypted connection to that website. The browser finds the public key of an SSL certificate installed on the website, which is used to encrypt any data you send, then the private key decrypts it.

## **RSA Encryption in Node.js**

```js
const { publicEncrypt, privateDecrypt } = require("crypto");
const { publicKey, privateKey } = require("./keypair");

const encryptedData = publicEncrypt(publicKey, Buffer.from(secretMessage));

console.log(encryptedData.toString("hex"));

const decryptedData = privateDecrypt(privateKey, encryptedData);

console.log(decryptedData.toString("utf-8"));
```

# 7. Signing

## Signing is the process of creating a digital signature of a message. A signature is a hash of the original message which is then encrypted with the sender’s private key.

## The signature can be verfied by the recipient using the public key of the sender. This can guarantee the the original message is authentic and unmodified.

## **RSA Signing in Node.js**

```js
const { createSign, createVerify } = require("crypto");
const { publicKey, privateKey } = require("./keypair");

const data = "this data must be signed";

/// SIGN

const signer = createSign("rsa-sha256");

signer.update(data);

const siguature = signer.sign(privateKey, "hex");

console.log(siguature);

/// VERIFY

const verifier = createVerify("rsa-sha256");

verifier.update(data);

const isVerified = verifier.verify(publicKey, siguature, "hex");

console.log(isVerified);
```
