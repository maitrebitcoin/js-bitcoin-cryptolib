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
        // init as a private key
        initAsPrivate( key, chainCode, depth ) {
            console.assert( typeof key == 'bigint' )
            console.assert( typeof chainCode == 'string' )
            console.assert( chainCode.length == 32,"chainCode must be 256 bits")            
            console.assert( typeof depth == 'number' )
            console.assert( depth >=  0 )
            console.assert( depth <= 255 )
            this.key       = key;
            this.chainCode = chainCode;        
            this.depth     = depth;  
            this.private   = true;
        }
        isExtendedKey() {return true;}
        isPrivateKey() {return this.private;}
        /** 
        * convert the extented key to raw buffer (serialisation)
        * * @returns {buffer} binairy buffer. ex: "0488ade400000000000000000096cfbe121203639....""
        */
        toRawBuffer() {
            var buf = '';
            // 4 byte: version bytes
            var nVersion = this.private  ? nSIGNATURE_PrivateKey : nSIGNATURE_PublicKey;
            buf += intTobigEndian32Buffer(nVersion) // mainnet: 0x0488B21E public, 0x0488ADE4 private
            // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
            buf +=  String.fromCharCode(this.depth   )
            // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
            buf += intTobigEndian32Buffer(0)
            // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
            buf += intTobigEndian32Buffer(0)
            // 32 bytes: the chain code
            buf +=  this.chainCode
            // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
            buf += "\x00" + BigInt256ToLowEndianBuffer( this.key)
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
            var version    = bigEndianBufferToInt( buffer.substring(0,4) )
            if (version == nSIGNATURE_PrivateKey)
                this.private  =  true
            else if (version == nSIGNATURE_PublicKey)
                this.private  =  false
            else
                return  {error:"unknown version header", version:hex(version) }; 
            // 1 byte: depth: 
            this.depth      =  buffer.charCodeAt(4)
            // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
            var fingerprint = bigEndianBufferToInt( buffer.substring(5,9) )
            // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
            var childNumber = bigEndianBufferToInt( buffer.substring(9,13) )
            // 32 bytes: the chain code    
            this.chainCode  =                       buffer.substring(13,45) 
            // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
            if (this.private)
                this.key    = bigEndianBufferTo256BitInt( buffer.substring(46,78) )
            else
                this.key    =                             buffer.substring(45,78) 
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

     bHardenedKey = i<0; // or i > 0x80000000
     var data;
     if (bHardenedKey) {
        // hardened child
        //Data = 0x00 || ser256(kpar) || ser32(i))
        data = "\x00" + extendedKey.key + intTobigEndian32Buffer(i)
     }
     else { 
        // normal chid
        // Data = serP(point(kpar)) || ser32(i)).
        // convert to 256 Bits integer
        var extkeyAsBigInt  = bigEndianBufferTo256BitInt( extendedKey.key)     
        // calculate P = K * G   
        var KPoint  = this.ecdsa.ec.pointGeneratorScalarMult( extkeyAsBigInt );
        // calc buffer 
        data = P.toBuffer() + intTobigEndian32Buffer(i)
    }
    // calculate hash from key and buffer
    var hash512 = hmac_sha512(  extendedKey.chainCode, data );
    // calculate résult
    // child key = parse256(IL) + kpar (mod n).
    var IL = bigEndianBufferTo256BitInt( hash512.substring(0,32) )
    var IR = hash512.substring(32, 64) 
    var childKey =  this.ecdsa.oField.add( IL, extendedKey.key )

    var res = new hdwallet.ExtendedKey()
    res.initAsPrivate( childKey, IR, i );
    return res;
}

/**
 *  get the master key
 * 
 * @returns {hdwallet.ExtendedKey} the master key (private key)
 */
getMasterKey() {
    // calculate HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    var hash512 = hmac_sha512( "Bitcoin seed", this.seed );
    // cut in 2 part 256 bits long
    var IL = hash512.substring(0, 32) 
    var IR = hash512.substring(32,64) 
    // init the extended private key :  key, chainCode, depth
    var key =  bigEndianBufferTo256BitInt( IL )
    var res = new hdwallet.ExtendedKey();
    res.initAsPrivate( key, IR, 0 );
    return res;
}
/**
 *  get a private key for a derivation path
 * @param   {string}  derivationPath the derivation path. ex: "m/0'/1"
 * @returns {hdwallet.ExtendedKey}   the master key (private key)
 */
getPrivateKeyFromPath( derivationPath ) {
    // master key ?
    if (derivationPath=='m') return getMasterKey()
    // get remaining path
    // ex : "0'/1"
    var nPos = derivationPath.indexOf("/")
    if (nPos<=0) {
        return {error:"invalid derivation path format",derivationPath:derivationPath};
    }
    var remainingPath = derivationPath.substr( nPos+1 );
    var indexI    = remainingPath.split()[0]; // ex =  "0'/1" => "0'"
    var lastChar  = indexI.substr( indexI.length-1 ) 
    var hardened  = (lastChar == "H") || (lastChar=="'") // H or ' accepted
    if (hardened)
        indexI = remainingPath.substr( 0, indexI.length-1 ) // remove ' ou H at the end
    var index     = parseInt(remainingPath)
    if (hardened)
        if (index = -index)
    // get master key
    var masterKey = getMasterKey();
    //@test : 1 derivation
    return _ckdPrivatr(masterKey, index)
}


}; // class hdwallet