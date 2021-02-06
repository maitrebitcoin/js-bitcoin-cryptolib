// hdwallet.js
// bip32 bitcoin wallet.
// see :
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki


function bufferFromHex( str ) {
    var buffer = ""
    str.match(/[\da-f]{2}/gi).map(function (h) {
        buffer += String.fromCharCode( parseInt(h, 16) )
    })

    return buffer;
}

/**
 *  encode a binary buffer to base58
 * 
 * @param   {string} buffer
 * @returns {string}
 */
function base58Encode( buffer, prefix ) {
    if (!prefix)
        prefix = ''
    var sBase = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    // convert to hexa
    var hexaBuf= hex(  prefix + buffer )
    // convert to number
    var numBufAndCrc = BigInt( "0x" + hexaBuf )
    // main loop : divive by 58 until numBuf go to 0.
    var res = ""
    var _58 = BigInt(58)
    while (numBufAndCrc>0) {
        var c = Number( numBufAndCrc % _58); // modulo
        // add char in front
        res = sBase[c] + res
        // next char, divide by 58
        numBufAndCrc = numBufAndCrc /  _58;
    }
    // add leading 1 for the "0" in start of <buffer>
    var nLeading0 = 0;
    while (buffer[nLeading0]==='\x00') nLeading0++;
    res = "1".repeat(nLeading0) + res

    return res
}
function base58CheckEncode( buffer, prefix ) {
    if (!prefix)
        prefix = ''
    // calc crc
    sBufCrc= sha256(sha256( prefix +buffer ))
    // get 4 first bytes
    sCrc = sBufCrc.substring(0,4); 

    var sBase = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    // convert to hexa
    var hexaBufAndCrc = hex(  buffer + sCrc )
    // convert to number
    var numBufAndCrc = BigInt( "0x" + hexaBufAndCrc )
    // main loop : divive by 58 until numBuf go to 0.
    var res = ""
    var _58 = BigInt(58)
    while (numBufAndCrc>0) {
        var c = Number( numBufAndCrc % _58); // modulo
        // add char in front
        res = sBase[c] + res
        // next char, divide by 58
        numBufAndCrc = numBufAndCrc /  _58;
    }
    // add leading 1 for the "0" in start of <buffer>
    var nLeading0 = 0;
    while (buffer[nLeading0]==='\x00') nLeading0++;
    res = "1".repeat(nLeading0) + res

    return res
}


class hdwallet {

// ------ types -----
    // represent a extended key for a hdwallet
    static ExtendedKey = class { 
        constructor( key, chainCode, depth ) {
            console.assert( typeof key == 'bigint' )
            console.assert( typeof chainCode == 'string' )
            console.assert( chainCode.length == 32,"chainCode must be 256 bits")            
            console.assert( typeof depth == 'number' )
            console.assert( depth >=  0 )
            console.assert( depth <= 255 )
            this.key       = key;
            this.chainCode = chainCode;        
            this.depth     = depth;  
        }
        isExtendedKey() {return true;}
        // convert to buffer (serialisation)
        toBuffer() {
            var buf = '';
            // 4 byte: version bytes
            buf += intTobigEndia32Buffer(0x0488ADE4) // mainnet: 0x0488B21E public, 0x0488ADE4 private
            // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
            buf +=  String.fromCharCode(this.depth   )
            // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
            buf += intTobigEndia32Buffer(0)
            // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
            buf += intTobigEndia32Buffer(0)
            // 32 bytes: the chain code
            buf +=  this.chainCode
            // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
            buf += "\x00" + BigInt256ToLowEndianBuffer( this.key)
            console.assert( buf.length == 78)
            return buf
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
        data = "\x00" + extendedKey.key + intTobigEndia32Buffer(i)
     }
     else { 
        // normal chid
        // Data = serP(point(kpar)) || ser32(i)).
        // convert to 256 Bits integer
        var extkeyAsBigInt  = lowEndianBufferTo256BitInt( extendedKey.key)     
        // calculate P = K * G   
        var KPoint  = this.ecdsa.ec.pointGeneratorScalarMult( extkeyAsBigInt );
        // calc buffer 
        data = P.toBuffer() + intTobigEndia32Buffer(i)
    }
    // calculate hash from key and buffer
    var hash512 = hmac_sha512(  extendedKey.chainCode, data );
    // calculate résult
    // child key = parse256(IL) + kpar (mod n).
    var IL = lowEndianBufferTo256BitInt( hash512.substring(0,32) )
    var IR = hash512.substring(32, 64) 
    var childKey =  this.ecdsa.oField.add( IL, extendedKey.key )

    var res = new hdwallet.ExtendedKey( childKey, IR, i );
    return res;
}

/**
 *  get the master key
 * 
 * @returns {hdwallet.ExtendedKey}
 */
getMasterKey() {
    // calculate HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    var hash512 = hmac_sha512( "Bitcoin seed", this.seed );
    // cut in 2 part 256 bits long
    var IL = lowEndianBufferTo256BitInt( hash512.substring(0,32) )
    var IR = hash512.substring(32, 64) 
    var res = new hdwallet.ExtendedKey( IL, IR, 0 );
    return res;
}


}; // class hdwallet