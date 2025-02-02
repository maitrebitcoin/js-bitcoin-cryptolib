# js-bitcoin-cryptolib

ECDSA secp256k1 ( Bitcoin digital signature scheme ) in Vanilla Javascript 
HD Wallet support (BIP32, BIP39, BIP49)

Does not refer to any external library for security reasons :

* Can be downloaded and run as is into any browser
* Does not require network access.

Can be tested online here : 
* https://maitrebitcoin.com/js-bitcoin-cryptolib/sample/createAccountSegwitNative.html
* https://maitrebitcoin.com/js-bitcoin-cryptolib/sample/lastBip39Word.html
* https://maitrebitcoin.com/js-bitcoin-cryptolib/sample/recoverAccount.html


Examples :


Generate a Bitcoin account.  ex : "bc1qacpwyw3hl4ley896a2l7alszmanlnu45u24jkl"
```
    // create a new wallet 
    var myWallet   = new BitcoinWallet(  WalletType.SEGWIT_NATIVE  );
    // generate from random 
    myWallet.initFromRandom()
    // get the mnemonic phrase for backup
    // ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
    var phrase       = myWallet.phrase
    // get the 1st public adress. 
    // ex : "bc1qacpwyw3hl4ley896a2l7alszmanlnu45u24jkl"
    var pubAdress0   =  myWallet.getPublicAddress(0)

```

Sign and verify a message with ECDSA
```
    var priv      = ecdsa.newPrivateKey();
    var pub       = ecdsa.publicKeyFromPrivateKey(priv);
    var signature = ecdsa.signMessage( "my message", priv )
    var res       = ecdsa.verifySignature( "my message", signature, pub )
    if (!res.ok) alert(res.message)
```