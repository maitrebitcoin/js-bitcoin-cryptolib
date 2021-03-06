# js-bitcoin-cryptolib

ECDSA secp256k1 ( Bitcoin digital signature scheme ) in Vanilla Javascript 
HD Wallet support (BIP32, BIP39, BIP49)


Does not refer to any external library for security reasons :

* Can be downloaded and run as is into any browser
* Does not require network access.

Examples :

Sign and verify a message with ECDSA
```
  var priv      = ecdsa.newPrivateKey();
  var pub       = ecdsa.publicKeyFormPrivateKey(priv);
  var signature = ecdsa.signMessage( "my message", priv )
  var res       = ecdsa.verifySignature( "my message", signature, pub )
  if (!res.ok) alert(res.message)
```

Generate a BIP-49 compatible Bitcoin Account.  ex : "3BRTnZiug1MdARwxbSw9KDPfxjDDW6D1YZ"
```
    // generate a random buffer
    var randomBuffer = getRandomBuffer(128)
    // calculate the mnemonic phrase from this buffer
    // ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
    var phrase       = bip39phraseFromRandomBuffer(randomBuffer)
    var seed         = seedFromPhrase(phrase)
    // create a new bip32 wallet
    var bip32Wallet   = new hdwallet( seed, WalletType.SEGWIT  );
    var pubAdress0   = bip32Wallet.getSegwitPublicAdressFromPath("m/49'/0'/0'/0", 0)
```
