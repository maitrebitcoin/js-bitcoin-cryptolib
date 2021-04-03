/**
 ****************************************************** 
 * @file    HdWallet.js 
 * @file    bip32  bitcoin hierarchical deterministic wallet support.
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see     https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

 
//  signature header for extended pub key 
const SignatureHeader = {
    PrivateKey_legacy   : 0x0488ADE4,  // ex :"xpriv..."
    PublicKey_legacy    : 0x0488B21E,
    PrivateKey_segwit   : 0x049d7878,  // ex :"ypriv..." 
    PublicKey_segwit    : 0x049d7cb2,
    PrivateKey_sgNative : 0x04b2430c,  // ex :"zprv..." 
    PublicKey_sgNative  : 0x04b24746     
 }
 // known derivation path
 const DerivationPath = {
    MASTERKEY       : "m",
    LEGACY_BIP44    : "m/44'/0'/0'",
    SEWITG_BIP49    : "m/49'/0'/0'",
    SW_NATIVE_BIP84 : "m/84'/0'/0'"
}


class HdWallet {
/** 
 *  create a new HdWallet from a seed 
 * @public
 * @param {string} seed 128 to 512 bits buffer  
 * @param {WalletType}  walletType WalletType.LEGACY, WalletType.SEGWIT or WalletType.SEGWIT_NATIVE
 */
constructor() {
    this.seed       = undefined;
    this.walletType = undefined
    this.ecdsa      = new ECDSA();
    // cache of extented private and public keys. 
    this.extPrivateKey_cache = [] 
    this.extPublicKey_cache  = [] 
}
/** 
 *  init HdWallet from a seed 
 * @public
 * @param {string} seed 128 to 512 bits buffer  
 * @param {WalletType}  walletType WalletType.LEGACY, WalletType.SEGWIT or WalletType.SEGWIT_NATIVE
 */
initFromSeed( seed, walletType ) {
    console.assert( seed.length >= 16 && seed.length <= 64 ,"seed must be between 128 and 512 bits")
    this.seed       = seed
    this.walletType = walletType

}
/** 
 *  init HdWallet from a extended private or public key. ex : "zpub6sAxdNfDsummUgnQ7y.." 
 * @public
 * @param {string} extKeyString58  extended public or private key in base 58 format. ex : "zpub6sAxdNfDsummUgnQ7y.." 
 * @throws {Error} if <extKeyString58> is invalid
 */
initFromExtendedKey( extKeyString58 ) {
    // decode  the string
    var extendedKey  =  this.getExtendedKeyFromStringBase58(extKeyString58)
    if (!extendedKey.isPrivateKey())
        this.readonly = true; // cannot send any fund
    this.walletType = extendedKey.walletType;        
//@TODO
    // check key
    if (extendedKey.depth != 3)
        throw _BuildError(LibErrors.Invalid_extkey_initwallet,{depth:extendedKey.depth});
    if (extendedKey.childNumber != 0x80000000)
        throw _BuildError(LibErrors.Invalid_extkey_initwallet,{childNumber:extendedKey.childNumber});
    if (extendedKey.walletType != WalletType.SEGWIT_NATIVE)
        throw _BuildError(LibErrors.Invalid_extkey_initwallet,"only segwit native is supported");        
    // calc derivation path
    var derivationPath = DerivationPath.SW_NATIVE_BIP84
    // add to cache
    if (extendedKey.isPrivateKey())
        this.extPrivateKey_cache[derivationPath] = extendedKey
    else
        this.extPublicKey_cache[derivationPath] = extendedKey
}
/**
 *  get the master key
 * @public
 * @returns {HdWalletExtendedKey} the master key (private key)
 */
getMasterKey() {
    // if not avail a all = we  have been init from an extended key
    if (!this.seed)
        throw _BuildError( LibErrors.MasterKey_notAvail )


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
    var masterKey = new HdWalletExtendedKey();
    masterKey.initAsPrivate( key, IR, undefined, this.ecdsa, this.walletType  );
    masterKey.depth       = 0;
    masterKey.childNumber = 0;
    // keep in cache
    this.extPrivateKey_cache[DerivationPath.MASTERKEY] = masterKey
    return masterKey;
}
/**
 *  get the extended private key for a derivation path
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/0'/1"
 * @returns {HdWalletExtendedKey}   the extended private key 
 * @throws  {Error} if <derivationPath> is invalid
 */
getExtendedPrivateKeyFromPath( derivationPath ) {
    // available in cache ?
    if (this.extPrivateKey_cache[derivationPath] )
        return this.extPrivateKey_cache[derivationPath];    
    // call internal recursive method
    var extPrivateKey = this._getPrivateKeyFromPathR(  derivationPath );
    // add to cache
    this.extPrivateKey_cache[derivationPath] = extPrivateKey;
    // success
    return extPrivateKey
}
/**
 *  get a extended public key for a derivation path
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/0'/1"
 * @returns {HdWalletExtendedKey}   the extended private key 
 * @throws  {Error} if <derivationPath> is invalid
 */
getExtendedPublicKeyFromPath( derivationPath ) {
    // avail in cache ?
    if (this.extPublicKey_cache[derivationPath] )
        return this.extPublicKey_cache[derivationPath];   
    // no private key avail ?
    if (this.readonly) {
        // call internal recursive method
        var extPrivateKey = this._getPublicKeyFromPathR(  derivationPath );
        // add to cache
        this.extPrivateKey_cache[derivationPath] = extPrivateKey;
        // success
        return extPrivateKey
    }

    // get the extended private key
    var extPrivateKey = this.getExtendedPrivateKeyFromPath(derivationPath);
    // get the public key
    var  extPublicKey = extPrivateKey.getExtendedPublicKey(this.ecdsa);
    // add to cache
    this.extPublicKey_cache[derivationPath] = extPublicKey;
    return extPublicKey;
}
/**
 *  get a public key for a derivation path + index
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/44'/0'/0'/0"
 * @param   {number}     index          index of the child key. 0 is the first accout
 * @returns {ECDSAPublicLKey} the extended private key 
 * @throws  {Error} if <derivationPath> is invalid
 */
getPublicKeyFromPath( derivationPath, index ) {
    // get the extendede public key
    var extPublicKey = this.getExtendedPublicKeyFromPath(derivationPath + "/" + index );
    // get the public key
    console.assert( extPublicKey.publicKey )
    return extPublicKey.publicKey;
}
/**
 *  get a private key for a derivation path + index
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/44'/0'/0'/0"
 * @param   {number}     index          index of the child key. 0 is the first accout
 * @returns {ECDSAPublicLKey} the extended private key 
 * @throws  {Error}           if <derivationPath> is invalid
 */
getPrivateKeyFromPath( derivationPath, index ) {
    // get the extendede public key
    var extPrivateKey = this.getExtendedPrivateKeyFromPath(derivationPath + "/" + index );
    // get the public key
    console.assert( extPrivateKey.privateKey )
    return extPrivateKey.privateKey;
}

/**
 * create a new extended key (public or private) from the base 58 string format
 * @param  {string} strBase58  ex "xprv9u5vS4oCRV5L6Jy7K1..."
 * @return {HdWalletExtendedKey} a public or private extended key
 * @throws {Error} if <derivationPath> is invalid
 */
getExtendedKeyFromStringBase58( strBase58 )
{
    // create a new key
    var extendeKey = new HdWalletExtendedKey() 
    // init from string
    var res = extendeKey.initFromStringBase58(strBase58)
    return extendeKey;
}

/**
 *   internal Child key derivation (CKD) functions for rprivate keys
 * @protected
 * @param  {HdWalletExtendedKey} extendedKey parent key
 * @param  {number} i key index (childNumber)
 * @return {HdWalletExtendedKey} child key
 * @throws {Error} if the operation is not possible
 */
_ckdPrivatr( extendedKey, i ) {
    console.assert( extendedKey.isExtendedKey() )

    var bHardenedKey = (i & 0x80000000) != 0; // or i > 0x80000000
    var data;
    var ecPoint // an Point on the ecdsa elliptic curve
  
    if (bHardenedKey) {
       // the extended key mut be a private key
       if (!extendedKey.isPrivateKey()) {
           throw _BuildError(LibErrors.Impossible_pubkey_derivation )
       }
       var key = extendedKey.privateKey.value
       // hardened child
       //Data = 0x00 || ser256(kpar) || ser32(i))
       data = "\x00" + bigEndianBufferFromBigInt256(key) + bigEndianBufferFromInt32(i)
    }
    else { 
       // normal chid         

       if (!extendedKey.isPrivateKey()) {
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


   var res = new HdWalletExtendedKey()
   res.childNumber = i

   if (!extendedKey.isPrivateKey()) {
        // The returned child key Ki is point(parse256(IL)) + Kpar.
        var ecPointIL    =  this.ecdsa.ec.pointGeneratorScalarMult( IL );
        var ecChildPoint =  this.ecdsa.ec.pointAdd( ecPointIL, extendedKey.publicKey.point );
        // returns a public key
        var pubKeyRes = new ECDSAPublicKey(ecChildPoint);
        res.initAsPublicKey( pubKeyRes, IR, this.walletType );
   }
   else {
       // return a private key
       var childPrivateKey =  this.ecdsa.gField.add( IL, extendedKey.privateKey.value )
       res.initAsPrivate( childPrivateKey, IR, extendedKey, this.ecdsa, this.walletType );
   }

   return res;
}

/**
 * internal function to parse a derivation path
 * @protected
 * @param   {string}  derivationPath  the derivation path. ex: "0'/1/2"
 * @returns {struct}  ex : { leftPath='0'/1',index:2,hardened:false  }
 * @throws  {Error} if <derivationPath> is invalid
 */
 _parseDerivationPath( derivationPath ) {
    // must start with "m/"
    if (derivationPath.substr(0,2) != "m/") {
        throw _BuildError( LibErrors.Invalid_derivation_path, {detail :"must start with 'm/'", derivationPath:derivationPath})
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
        throw _BuildError( LibErrors.Invalid_derivation_path, {detail :"index < 0", derivationPath:derivationPath })
    }
    if (rightPath=="") {
        throw _BuildError( LibErrors.Invalid_derivation_path, {detail :"rightPath is empty",derivationPath:derivationPath })
    }    
    if (leftPath=="") {
        throw _BuildError( LibErrors.Invalid_derivation_path, {detail :"leftPath is empty", derivationPath:derivationPath })
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
 * @returns {HdWalletExtendedKey}   the extended private key 
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
/**
 *  get a private key for a derivation path + parent R. 
 *  recursive internal function
 * @protected
 * @param   {string}  derivationPath  the derivation path. ex: "0'/1"
 * @returns {HdWalletExtendedKey}   the extended private key 
 */
_getPublicKeyFromPathR( derivationPath ) {
    // if derivationPath is the master key
    if (derivationPath==DerivationPath.MASTERKEY) 
        throw _BuildError( LibErrors.MasterKey_notAvail );
    // parse derivationPath
    var parsedPath = this._parseDerivationPath(derivationPath)

    // recursive call to get the parent key
    var extParentKey = this.getExtendedPublicKeyFromPath( parsedPath.leftPath )

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

}; // class HdWallet

// ------ types -----

// represent a extended key for a HdWallet
class HdWalletExtendedKey  { 
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
     *  @param {HdWalletExtendedKey} parentKey, optionnal (for mastker key only)
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
     * @return {HdWalletExtendedKey} the corresponding public extended key 
    */
    getExtendedPublicKey(ecdsa) {
        console.assert( ecdsa, "ecdsa must be present" )
        console.assert( this.isPrivateKey() )
        // calculate  cdsa public key
        var publicKey  = ecdsa.publicKeyFromPrivateKey( this.privateKey )
        // create an extended key
        var resKey = new HdWalletExtendedKey();
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
    * init from a base58 encoding
    * @param   {string} str58 a base58 endoded string 
    * @throws  {Error} if <str58> is invalid
    */
    initFromStringBase58( str58 ) {
        // decode string to buffer. throw Error if <str58> is invalid
        var buffer =  base58CheckDecode(str58)
        // check decoded buffer length
        if (buffer.length!=78) 
            throw _BuildError( LibErrors.Invalid_extkey_buffer_len,  {length:buffer.length }); // failed
        // get 1st 4 byte => version bytes
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
                this.private     =  false
                this.walletType  =  WalletType.SEGWIT 
                break;        
            case SignatureHeader.PrivateKey_sgNative:
                this.private     =  true
                this.walletType  =  WalletType.SEGWIT_NATIVE 
                break;                                   
            case SignatureHeader.PublicKey_sgNative:
                this.private     =  false
                this.walletType  =  WalletType.SEGWIT_NATIVE 
                break;                                
            default:
                throw _BuildError( LibErrors.Invalid_extkey_buffer_header, { version:hex(version) }) 
        }
        console.assert( this._getVersionHeader() == version )
        // 1 byte: depth: 
        this.depth      =  buffer.charCodeAt(4)
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        this.parentFingerprint = int32FromBigEndianBuffer( buffer.substring(5,9) )
        // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
        this.childNumber = int32FromBigEndianBuffer( buffer.substring(9,13) ) >>> 0
        // 32 bytes: the chain code    
        this.chainCode       =                       buffer.substring(13,45) 
        // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
        if (this.private) {
            var  privkeyVal = bigInt256FromBigEndianBuffer( buffer.substring(46,78) )
            this.privateKey = new ECDSAPrivateKey( privkeyVal )
        }
        else {
            var pubKeyBuf   =                               buffer.substring(45,78) 
            var ecdsa = new ECDSA()                  
            this.publicKey = ecdsa.publicKeyFromBuffer(pubKeyBuf);
        }
        // success
    }
    /**
     * get version header
     * @returns {number} ex : SIGNATURE_PrivateKey_Legacy
     */
    _getVersionHeader()  {
        if  (this.walletType == WalletType.SEGWIT_NATIVE )  {
            return this.private  ? SignatureHeader.PrivateKey_sgNative  
                                    : SignatureHeader.PublicKey_sgNative;
            }            
        if  (this.walletType == WalletType.SEGWIT )  {
            return this.private  ? SignatureHeader.PrivateKey_segwit  
                                : SignatureHeader.PublicKey_segwit;
        }
        if  (this.walletType == WalletType.LEGACY )  {
            return this.private ? SignatureHeader.PrivateKey_legacy  
                                : SignatureHeader.PublicKey_legacy;
        }            
        // if the type of wallet is not set, return legacy values
        return this.private ? SignatureHeader.PrivateKey_legacy  : SignatureHeader.PublicKey_legacy;
    }        
};// static ExtendedKey = class {


