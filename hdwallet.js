/**
 ****************************************************** 
 * @file    hdwallet.js 
 * @file    bip32 bitcoin wallet support.
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see     https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

const nSIGNATURE_PrivateKey = 0x0488ADE4
const nSIGNATURE_PublicKey  = 0x0488B21E

class hdwallet {

// ------ types -----
    // represent a extended key for a hdwallet
    static ExtendedKey = class { 
        constructor() {
        }
        /**
         *  init as a private key
         *  @param {bugInt} key       256 bits key part of the extended key
         *  @param {buffer}chainCode  256 bits chain code part of the extended key
         */
        initAsPrivate( key, chainCode, parentKey ) {
            console.assert( typeof key == 'bigint' )
            console.assert( typeof chainCode == 'string' )
            console.assert( chainCode.length == 32,"chainCode must be 256 bits")     
  
            this.key       = key;
            this.chainCode = chainCode;        
            this.private   = true;
            if (parentKey) {
                console.assert( parentKey.private, "parent of a private key lust be a private key")          
                // calculate key identifier. same as a legacy Bitcoin adress :              
                var ecdsa      = new ECDSA();
                var privateKey = ecdsa.privateKeyFromBigInt( parentKey.key )
                var publicKey  = ecdsa.publicKeyFormPrivateKey( privateKey )
                var publicKeySerialized = publicKey.toBuffer();
                var keyId               = ripemd160( sha256( publicKeySerialized ))
                // the first 32 bits of the identifier 
                this.parentFingerprint = int32FromBigEndianBuffer( keyId.substr(0,4) )
            }
            else {
                this.parentFingerprint = 0 // master key
            }
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
            var nVersion = this.private  ? nSIGNATURE_PrivateKey : nSIGNATURE_PublicKey;
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
            buf += "\x00" + bigEndianBufferFromBigInt256( this.key)
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
            if (version == nSIGNATURE_PrivateKey)
                this.private  =  true
            else if (version == nSIGNATURE_PublicKey)
                this.private  =  false
            else
                return  {error:"unknown version header", version:hex(version) }; 
            // 1 byte: depth: 
            this.depth      =  buffer.charCodeAt(4)
            // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
            this.fingerprint = int32FromBigEndianBuffer( buffer.substring(5,9) )
            // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
            this.childNumber = int32FromBigEndianBuffer( buffer.substring(9,13) )
            // 32 bytes: the chain code    
            this.chainCode  =                       buffer.substring(13,45) 
            // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
            if (this.private)
                this.key    = bigInt256FromBigEndianBuffer( buffer.substring(46,78) )
            else
                this.key    =                               buffer.substring(45,78) 
            // success
        }
    };

// --- methods --------

// construct a new hdwallet from a seed of 512 bytes
constructor( seed ) {
    console.assert( seed.length == 64,"seed must be 512 bits")
    this.seed = seed
    this.ecdsa = new ECDSA();
}

// internal Child key derivation (CKD) functions for rprivate keys
_ckdPrivatr( extendedKey, i ) {
     console.assert( extendedKey.isExtendedKey() )

     var bHardenedKey = (i & 0x80000000) != 0; // or i > 0x80000000
     var data;
     if (bHardenedKey) {
        // hardened child
        //Data = 0x00 || ser256(kpar) || ser32(i))
        data = "\x00" + bigEndianBufferFromBigInt256(extendedKey.key) + bigEndianBufferFromInt32(i)
     }
     else { 
        // normal chid
        // Data = serP(point(kpar)) || ser32(i)).
        // calculate P = K * G   
        var KPoint  = this.ecdsa.ec.pointGeneratorScalarMult( extendedKey.key );
        // calc buffer 
        data = KPoint.toBuffer() + bigEndianBufferFromInt32(i)
    }
    // calculate hash from key and buffer
    var hash512 = hmac_sha512(  extendedKey.chainCode, data );
    // calculate résult
    // child key = parse256(IL) + kpar (mod n).
    var IL = bigInt256FromBigEndianBuffer( hash512.substring(0,32) )
    var IR = hash512.substring(32, 64) 
    var childKey =  this.ecdsa.oField.add( IL, extendedKey.key )

    var res = new hdwallet.ExtendedKey()
    res.initAsPrivate( childKey, IR, extendedKey );
    res.childNumber = i
    return res;
}

/**
 *  get the master key
 * @public
 * @returns {hdwallet.ExtendedKey} the master key (private key)
 */
getMasterKey() {
    // calculate HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    var hash512 = hmac_sha512( "Bitcoin seed", this.seed );
    // cut in 2 part 256 bits long
    var IL = hash512.substring(0, 32) 
    var IR = hash512.substring(32,64) 
    // init the extended private key :  key, chainCode
    var key =  bigInt256FromBigEndianBuffer( IL )
    var masterKey = new hdwallet.ExtendedKey();
    masterKey.initAsPrivate( key, IR );
    masterKey.depth       = 0;
    masterKey.childNumber = 0;
    return masterKey;
}
/**
 *  get a private key for a derivation path
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/0'/1"
 * @returns {hdwallet.ExtendedKey}   the extended private key 
 */
getPrivateKeyFromPath( derivationPath ) {
    // master key ?
    if (derivationPath=='m') return this.getMasterKey()
    // must start with "m/"
    if (derivationPath.substr(0,2) != "m/") {
        return {error:"invalid derivation path format. must start with 'm/'",derivationPath:derivationPath};
    }
    // get remaining path
    // ex : "0'/1"
    var remainingPath = derivationPath.substr( 2 );
    // call internal recursive func
    var masterKey = this.getMasterKey()
    var res = this._getPrivateKeyFromPathR( remainingPath, masterKey, 1 );
    if (res.error) {
        // error
        res.derivationPath = derivationPath;
        return res;
    }
    // ok
    return res
}
/**
 *  get a private key for a derivation path + parent R. 
 *  recursive internal function
 * @protected
 * @param   {string}  derivationPath  the derivation path. ex: "0'/1"
 * @returns {hdwallet.ExtendedKey}   the extended private key 
 */
_getPrivateKeyFromPathR( derivationPath, parentKey, depth ) {
     // extraction remaining path
    // ex : "0'/1"  => "0'" and "1"
    var nPos = derivationPath.indexOf("/")
    var leftPath  = ""
    var rightPath = ""
    if (nPos<=0) {
        // no more child ckeys
        leftPath = derivationPath
    }
    else  {
        leftPath  = derivationPath.substr( 0, nPos );    
        rightPath = derivationPath.substr( nPos+1 );
    }

    var lastChar  = leftPath.substr( leftPath.length-1 ) 
    var hardened  = (lastChar == "H") || (lastChar=="'") // H or ' accepted
    if (hardened)
        leftPath = leftPath.substr( 0, leftPath.length-1 ) // remove ' ou H at the end
    // convert path to integer. ex : "43" => 43
    var index     = parseInt(leftPath)
    // test for invalid format
    if (index<=0 && leftPath!='0') {
        return {error:"invalid invalid derivation path format.", invalidParsed:leftPath }
    }
    if (hardened)
        index = 0x80000000 + index;
    // get master key
    var masterKey = this.getMasterKey();
    //@test : 1 derivation
    var extendedKey = this._ckdPrivatr(parentKey, index)
    extendedKey.depth = depth;
    console.assert(extendedKey.childNumber == index);
    // if  no more child ckeys
    if (rightPath=="") 
        return extendedKey;
     
    // recursive call on rhe remaining path <rightPath>
    var extKeyChild = this._getPrivateKeyFromPathR( rightPath, extendedKey, depth+1 )
    return extKeyChild;
}


}; // class hdwallet