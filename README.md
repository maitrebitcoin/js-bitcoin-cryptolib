# js-bitcoin-cryptolib

ECDSA secp256k1 ( Bitcoin digital signature scheme ) in javascript 

Does not refer to any external library for security reasons :

* Can be downloaded and run as is into any browser
* Does not require network access.

Exemple :
```
  var priv      = ecdsa.newPrivateKey();
  var pub       = ecdsa.publicKeyFormPrivateKey(priv);
  var signature = ecdsa.signMessage( "my message", priv )
  var res       = ecdsa.verifySignature( "my message", signature, pub )
  if (!res.ok) alert(res.message)
```
