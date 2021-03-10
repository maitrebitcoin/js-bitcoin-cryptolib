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

Generate a BIP-49 compatible Bitcoin account.  ex : "3BRTnZiug1MdARwxbSw9KDPfxjDDW6D1YZ"
```
    // create a new wallet 
    var myWallet   = new BitcoinWallet(  WalletType.SEGWIT_NATIVE  );
    // generate a random buffer
    var randomBuffer = myWallet.getRandomBuffer(128)
    // calculate the mnemonic phrase from this buffer
    // ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
    var phrase       = bip39phraseFromRandomBuffer(randomBuffer)
    var seed         = seedFromPhrase(phrase)
    // use the seed a the base for all adresses calculations
    myWallet.initFromSeed(seed)
    // get the 1st public adress. 
    var pubAdress0   =  myWallet.getPublicAddress(0)
```
