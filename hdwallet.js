/**
 ****************************************************** 
 * @file    hdwallet.js 
 * @file    bip32  bitcoin hierarchical deterministic wallet support.
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see     https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

 // hd wallet types
const WalletType = {
    LEGACY : "legacy-bip44",
    SEGWIT : "segwit-bip49"
}
//  signature header for extended pub key 
const SignatureHeader = {
    PrivateKey_legacy : 0x0488ADE4,  // ex :"xpriv..."
    PublicKey_legacy  : 0x0488B21E,
    PrivateKey_segwit : 0x049d7878,  // ex :"ypriv..." 
    PublicKey_segwit  : 0x049d7cb2
 }
 // known derivation path
const DerivationPath = {
     MASTERKEY      : "m",
     LEGACY_BIP44   : "m/44'/0'/0'/0",
     SEWITG_BIP49   : "m/49'/0'/0'/0"
}


class hdwallet {
/** 
 *  create a new hdwallet from a seed 
 * @public
 * @param {string} seed 128 to 512 bits buffer  
 * @param {WalletType}  walletType WalletType.LEGACY or WalletType.SEGWIT
 */
constructor( seed, walletType ) {
    console.assert( seed.length >= 16 && seed.length <= 64 ,"seed must be between 128 and 512 bits")
    this.seed       = seed
    this.walletType = walletType
    this.ecdsa      = new ECDSA();
    // cache of extented private and public keys. 
    this.extPrivateKey_cache = [] 
    this.extPublicKey_cache  = [] 
}
/**
 *  get the master key
 * @public
 * @returns {hdwallet.ExtendedKey} the master key (private key)
 */
getMasterKey() {
    // avail in cache ?
    if (this.extPrivateKey_cache[DerivationPath.MASTERKEY] )
        return this.extPrivateKey_cache[DerivationPath.MASTERKEY];
    // calculate HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    var hash512 = hmac_sha512( "Bitcoin seed", this.seed );
    // cut in 2 part 256 bits long
    var IL = hash512.substring(0, 32) 
    var IR = hash512.substring(32,64) 
    // init the extended private key :  key, chainCode
    var key =  bigInt256FromBigEndianBuffer( IL )
    var masterKey = new hdwallet.ExtendedKey();
    masterKey.initAsPrivate( key, IR, undefined, this.ecdsa, this.walletType  );
    masterKey.depth       = 0;
    masterKey.childNumber = 0;
    // keep in cache
    this.extPrivateKey_cache[DerivationPath.MASTERKEY] = masterKey
    return masterKey;
}
/**
 *  get a private key for a derivation path
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/0'/1"
 * @returns {hdwallet.ExtendedKey}   the extended private key 
 */
getExtendedPrivateKeyFromPath( derivationPath ) {
    // avail in cache ?
    if (this.extPrivateKey_cache[derivationPath] )
        return this.extPrivateKey_cache[derivationPath];    

    // call internal recursive method
    var extPrivateKey = this._getPrivateKeyFromPathR(  derivationPath );
    if (extPrivateKey.error) {
        // error
        extPrivateKey.derivationPath = derivationPath;
        return extPrivateKey;
    }
     // keep in cache
    this.extPrivateKey_cache[derivationPath] = extPrivateKey;
    // success
    return extPrivateKey
}
/**
 *  get a extended public key for a derivation path
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/0'/1"
 * @returns {hdwallet.ExtendedKey}   the extended private key 
 */
getExtendedPubliceKeyFromPath( derivationPath ) {
    // avail in cache ?
    if (this.extPublicKey_cache[derivationPath] )
        return this.extPublicKey_cache[derivationPath];    
    // get the extendede private key
    var extPrivateKey = this.getExtendedPrivateKeyFromPath(derivationPath);
    if (extPrivateKey.error) 
        return extPrivateKey; // failed
    // get the public key
    var  extPublicKey = extPrivateKey.getExtendedPublicKey(this.ecdsa);
    // keep in cache
    this.extPublicKey_cache[derivationPath] = extPublicKey;
    return extPublicKey;
}
/**
 *  get a public key for a derivation path + index
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/44'/0'/0'/0"
 * @param   {int}     index          index of the child key. 0 is the first accout
 * @returns {ECDSA.PublicLKey} the extended private key 
 */
getPublicKeyFromPath( derivationPath, index ) {
    // get the extendede public key
    var extPublicKey = this.getExtendedPubliceKeyFromPath(derivationPath + "/" + index );
    if (extPublicKey.error) 
        return extPublicKey; // failed
    // get the public key
    console.assert( extPublicKey.publicKey )
    return extPublicKey.publicKey;

}
/**
 *  get a legacy public adress for a derivation path + index. 
 *  
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/44'/0'/0'/0"
 * @param   {int}     index          index of the child key. 0 is the first accout
 * @returns {stringy} P2PKH address = legacy format. ex : "1E3B4m6BSw7v2A7TiA2YxDTXBZjFEpBmPN"      
 */
getLegacyPublicAdressFromPath( derivationPath, index ) {
    // get the extendede public key
    var extPublicKey = this.getExtendedPubliceKeyFromPath(derivationPath + "/" + index );
    if (extPublicKey.error) 
        return extPublicKey; // failed
    console.assert( extPublicKey.publicKey )
    // serialised public key to raw buffer
    var publicKeySerialized = extPublicKey.publicKey.toBuffer();
    // legacy bitcoin format :
    var hash               = ripemd160( sha256( publicKeySerialized ) ) 
    var btcAdress          = base58CheckEncode( hash,  PREFIX_P2PKH );
    return btcAdress
}
/**
 *  get a sawigt public adress for a derivation path + index. 
 *  
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/49'/0'/0'/0"
 * @param   {int}     index          index of the child key. 0 is the first accout
 * @returns {stringy} P2PKH address = legacy format. ex : "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX"      
 */
getSegwitPublicAdressFromPath( derivationPath, index ) {
    // get the extendede public key
    var extPublicKey = this.getExtendedPubliceKeyFromPath(derivationPath + "/" + index );
    if (extPublicKey.error) 
        return extPublicKey; // failed
    console.assert( extPublicKey.publicKey )
    // serialised public key to raw buffer
    var publicKeySerialized = extPublicKey.publicKey.toBuffer();
    // bitcoin P2WPKH format :
    // If the version byte is 0, and the witness program is 20 bytes:
    // It is interpreted as a pay-to-witness-script-hash (P2WSH) program. 
    // NB : OP_HASH160 is ripemd160( sha256( x ) )
    var hashKey            = ripemd160( sha256( publicKeySerialized ) )
    var scriptSig          = '\x00\x14' + hashKey // \x00 : version byte, \x14=20   witness program
    var addressBytes       = ripemd160( sha256( scriptSig)  )       
    var btcAdress          = base58CheckEncode( addressBytes,  PREFIX_P2SH );
    return btcAdress
}




/**
 *   internal Child key derivation (CKD) functions for rprivate keys
 * @protected
 * @param  {hdwallet.ExtendedKey} extendedKey parent key
 * @param  {integer} i key index (childNumber)
 * @return {hdwallet.ExtendedKey} child key
 */
_ckdPrivatr( extendedKey, i ) {
    console.assert( extendedKey.isExtendedKey() )

    var bHardenedKey = (i & 0x80000000) != 0; // or i > 0x80000000
    var data;
  
    if (bHardenedKey) {
       // the extended key mut be a private key
       if (!extendedKey.isPrivateKey()) {
           return {error:"hardened derivation of a public key is not possible."}
       }
       var key = extendedKey.privateKey.value
       // hardened child
       //Data = 0x00 || ser256(kpar) || ser32(i))
       data = "\x00" + bigEndianBufferFromBigInt256(key) + bigEndianBufferFromInt32(i)
    }
    else { 
       // normal chid         
       var ecPoint // an Point on the ecdsa elliptic curve
       if (!extendedKey.isPrivateKey()) {
           // t
           ecPoint  = extendedKey.publicKey.point;
       }
       else
       {
           var key = extendedKey.privateKey.value                
           // calculate P = K * G   
           ecPoint  = this.ecdsa.ec.pointGeneratorScalarMult( key );
       }
       // Data = serP(point(kpar)) || ser32(i)).        
       // calc buffer 
       data = ecPoint.toBuffer() + bigEndianBufferFromInt32(i)
   }
   // calculate hash from key and buffer
   var hash512 = hmac_sha512(  extendedKey.chainCode, data );
   // calculate résult
   // child key = parse256(IL) + kpar (mod n).
   var IL = bigInt256FromBigEndianBuffer( hash512.substring(0,32) )
   var IR = hash512.substring(32, 64) 
   var childPrivateKey =  this.ecdsa.gField.add( IL, extendedKey.privateKey.value )

   var res = new hdwallet.ExtendedKey()
   res.initAsPrivate( childPrivateKey, IR, extendedKey, this.ecdsa, this.walletType );
   res.childNumber = i
   return res;
}

/**
 * parse a derivation path
 * @protected
 * @param   {string}  derivationPath  the derivation path. ex: "0'/1/2"
 * @returns {struct}  ex : { leftPath='0'/1',index:2,hardened:false  }
 */
 _parseDerivationPath( derivationPath ) {
    // must start with "m/"
    if (derivationPath.substr(0,2) != "m/") {
        throw {error:"invalid derivation path format. must start with 'm/'",derivationPath:derivationPath};
    }        
    // ex : "0'/1/2"  => "0'/1/" and "1"
    var nPos = derivationPath.lastIndexOf("/")
    var leftPath  = ""
    var rightPath = ""
    if (nPos<=0) {
        // no more child keys
        leftPath = derivationPath
    }
    else  {
        leftPath  = derivationPath.substr( 0, nPos );    
        rightPath = derivationPath.substr( nPos+1 );
    }
    var lastChar  = rightPath.substr( rightPath.length-1 ) 
    var hardened  = (lastChar == "H") || (lastChar=="'") // H or ' accepted
    if (hardened)
        rightPath = rightPath.substr(0, rightPath.length-1) // remove ' or H
     // convert path to integer. ex : "43" => 43
    var index     = parseInt(rightPath)

    // test for invalid format
    if (index<=0 && rightPath!='0') {
        throw {error:"invalid derivation path format.", derivationPath:derivationPath }
    }
    if (rightPath=="") {
        throw {error:"invalid derivation path format.", derivationPath:derivationPath }
    }    
    if (leftPath=="") {
        throw {error:"invalid derivation path format.", derivationPath:derivationPath }
    }        
    // success
    return { leftPath:leftPath,
             index:   index,
             hardened:hardened  };
}

/**
 *  get a private key for a derivation path + parent R. 
 *  recursive internal function
 * @protected
 * @param   {string}  derivationPath  the derivation path. ex: "0'/1"
 * @returns {hdwallet.ExtendedKey}   the extended private key 
 */
_getPrivateKeyFromPathR( derivationPath ) {
    // if derivationPath is the master key
    if (derivationPath==DerivationPath.MASTERKEY) 
        return this.getMasterKey();
    // parse derivationPath
    var parsedPath = this._parseDerivationPath(derivationPath)

    // recursive call to get the parent key
    var extParentKey = this.getExtendedPrivateKeyFromPath(  parsedPath.leftPath )

    // calc effective key index
    var index     = parsedPath.index;
    if (parsedPath.hardened)
        index = 0x80000000 + index;
    // calc derived key
    var extChildKey = this._ckdPrivatr(extParentKey, index)
    extChildKey.depth = extParentKey.depth+1;
    console.assert(extChildKey.childNumber == index);
    return extChildKey;
}

// ------ types -----
    // represent a extended key for a hdwallet
    static ExtendedKey = class { 
        /**
         * basic constructeur. to be completed with a call to initAsPrivate() or initFromStringBase58()
         * @public
         */
        constructor() {
        }
        /**
         *  init as a private key
         *  @param {bigInt} key        256 bits ecdsa private key
         *  @param {buffer} chainCode  256 bits chain code
         *  @param {hdwallet.ExtendedKey} parentKey, optionnal (for mastker key only)
         *  @param {ECDSA} ecdsa                     an instance of the ECDSA class to calculate keys. required.
         */
        initAsPrivate( key, chainCode, parentKey, ecdsa, walletType) {
            console.assert( typeof key == 'bigint' )
            console.assert( typeof chainCode == 'string' )
            console.assert( chainCode.length == 32,"chainCode must be 256 bits")     
            console.assert( ecdsa )     
            console.assert( walletType )    
 
            this.private    = true;
            this.privateKey = ecdsa.privateKeyFromBigInt( key );
            this.chainCode  = chainCode;        
            this.walletType = walletType
            if (parentKey) {
                console.assert( parentKey.private, "parent of a private key must be a private key")          
                // calculate key identifier : 32 first bit of hash( publickey )       
                var publicKey           = ecdsa.publicKeyFromPrivateKey( parentKey.privateKey )
                var publicKeySerialized = publicKey.toBuffer();
                var keyId               = ripemd160( sha256( publicKeySerialized ) ) // same hash as bitcoin public adress
                // the first 32 bits of the identifier 
                this.parentFingerprint = int32FromBigEndianBuffer( keyId.substr(0,4) )
            }
            else {
                this.parentFingerprint = 0 // master key
            }
        }
        /**
         *  init as a public key
         *  @param {CEDSA.PublicKey} key        ecdsa public key
         *  @param {buffer}          chainCode  256 bits chain code
         */        
        initAsPublicKey( key, chainCode, walletType ) {
            console.assert( key.isPublicKey() )
            console.assert( typeof chainCode == 'string' )
            console.assert( chainCode.length == 32,"chainCode must be 256 bits")     
            console.assert( walletType ) 
  
            this.private   = false;
            this.publicKey = key;
            this.chainCode = chainCode;   
            this.walletType = walletType     
        }
        /**
         * returns the extended public key if we are a private key
         * @param  {ECDSA} ecdsa  an instance of the ECDSA class to calculate keys. 
         * @return {hdwallet.ExtendedKey} the corresponding public extended key 
        */
        getExtendedPublicKey(ecdsa) {
            console.assert( ecdsa, "ecdsa must be present" )
            console.assert( this.isPrivateKey() )
            // calculate  cdsa public key
            var publicKey  = ecdsa.publicKeyFromPrivateKey( this.privateKey )
            // create an extended key
            var resKey = new hdwallet.ExtendedKey();
            resKey.initAsPublicKey(  publicKey,  this.chainCode,  this.walletType );
            resKey.parentFingerprint = this.parentFingerprint 
            resKey.depth             = this.depth
            resKey.childNumber       = this.childNumber
            return resKey;w
        }
        isExtendedKey() {return true;}
        isPrivateKey() {return this.private;}
        /** 
        * convert the extented key to raw buffer (serialisation)
        * * @returns {buffer} binairy buffer. ex: "0488ade400000000000000000096cfbe121203639....""
        */
        toRawBuffer() {
            //  <this.depth, .parentFingerprint, .childNumber>  bmust be defined a this point
            console.assert( typeof this.depth == 'number' )      
            console.assert( typeof this.parentFingerprint == 'number' )      
            console.assert( typeof this.childNumber == 'number' )      
            console.assert( this.depth >=  0 )
            console.assert( this.depth <= 255 )            
            var buf = '';
            // 4 byte: version bytes
            var nVersion = this._getVersionHeader()
            buf += bigEndianBufferFromInt32(nVersion) // mainnet: 0x0488B21E public, 0x0488ADE4 private
            // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
            buf +=  String.fromCharCode(this.depth   )
            // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
            buf += bigEndianBufferFromInt32(this.parentFingerprint)
            // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
            buf += bigEndianBufferFromInt32(this.childNumber)
            // 32 bytes: the chain code
            buf +=  this.chainCode
            // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
            if (this.private)
                buf += "\x00" + bigEndianBufferFromBigInt256( this.privateKey.value )
            else
                buf += this.publicKey.toBuffer()
            console.assert( buf.length == 78)
            return buf
        }
        /** 
        * convert the extented key to a base58 endoded string
        * @returns {string} ex: "xprv9s21ZrQH143K3ZSfM..."      
        */
        toStringBase58() {
            // encode buffer with CRC in base 58
            var buffer =  this.toRawBuffer();
            return base58CheckEncode( buffer )
        }
        /**
         * get version header
         * @returns {int} ex : SIGNATURE_PrivateKey_Legacy
         */
        _getVersionHeader()  {
            if  (this.walletType == WalletType.SEGWIT )  {
               return this.private  ? SignatureHeader.PrivateKey_segwit  : SignatureHeader.PublicKey_segwit;
            }
            if  (this.walletType == WalletType.LEGACY )  {
                return this.private ? SignatureHeader.PrivateKey_legacy  : SignatureHeader.PublicKey_legacy;
            }            
            // if the type of wallet is not set, return legacy values
            return this.private ? SignatureHeader.PrivateKey_legacy  : SignatureHeader.PublicKey_legacy;
        }

        /** 
        * init from a base58 encoding
        * @param   {sting} str58 a base58 endoded string 
        * @returns {error} undefined if no error. a  objet with an error member otherwise
        */
        initFromStringBase58( str58 ) {
            // decocode string to buffer
            var buffer =  base58CheckDecode(str58)
            if (buffer.error)
                return buffer; // failed
            // must be 78 bytes
            if (buffer.length!=78) 
                return {error:"invalid buffer length, must be 78", length:buffer.length }; // failed
            // 4 byte: version bytes
            var version    = int32FromBigEndianBuffer( buffer.substring(0,4) )
            switch (version) {
                case SignatureHeader.PrivateKey_legacy:
                    this.private     =  true
                    this.walletType  =  WalletType.LEGACY
                    break;
                case SignatureHeader.PublicKey_legacy:
                    this.private     =  false
                    this.walletType  =  WalletType.LEGACY
                    break;
                case SignatureHeader.PrivateKey_segwit:
                    this.private     =  true
                    this.walletType  =  WalletType.SEGWIT 
                    break;
                case SignatureHeader.PublicKey_segwit:
                    this.private    =  false
                    this.walletType  =  WalletType.SEGWIT 
                    break;                    
                default:
                    throw  {error:"unknown version header", version:hex(version) }; 
            }
            console.assert( _getVersionHeader() == version )
            // 1 byte: depth: 
            this.depth      =  buffer.charCodeAt(4)
            // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
            this.parentFingerprint = int32FromBigEndianBuffer( buffer.substring(5,9) )
            // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
            this.childNumber = int32FromBigEndianBuffer( buffer.substring(9,13) )
            // 32 bytes: the chain code    
            this.chainCode       =                       buffer.substring(13,45) 
            // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
            if (this.private) {
                var  privkeyVal = bigInt256FromBigEndianBuffer( buffer.substring(46,78) )
                this.privateKey = new ECDSA.PrivateKey( privkeyVal )
            }
            else {
                var pubKeyBuf   =                               buffer.substring(45,78) 
                var ecdsa = new ECDSA()                  
                this.publicKey = ecdsa.publicKeyFromBuffer(pubKeyBuf);
            }
            // success
        }
    };// static ExtendedKey = class {


}; // class hdwallet