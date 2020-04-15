# JavaEncryption
_Some encryption algorythms_

## Synchronous Encryption Algorythms
_Algorythms with a single key_

- [CaesarCipher.java](./CaesarCipher.java) - **INSECURE!!!**

## Asynchronous Encryption Algorythms
_Algorythms with a public and a private key_

- [AES.java](./AES.java)

## Hashing Functions
_Hashing Functions_

- HashedPassword.java](./HashedPassword.java) (using SHA-256 and a salt by default, which is a very slow hashing algorythm) - **for Passwords**
- ~~[HashedData.java](./HashedData.java)~~ () - **for Anything except passwords**

**Note:** HashedPasswords should extend HashedData later because the only difference is the hashing algorithm and that you use a salt for passwords.
