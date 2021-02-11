/**
 ****************************************************** 
 * @file    hdwallet.js 
 * @file    bip32 bitcoin wallet.
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see     https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * 
 * @license LGPL-3.0 
 ******************************************************
 */


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
            this.private   = true;
        }
        isExtendedKey() {return true;}
        isPrivateKey() {return this.private;}
        // convert to raw buffer (serialisation)
        // ex: 0488ade400000000000000000096cfbe1212036394874c07eadf5a657fb782b30a1518551b039099d4ace1754100d9af112377807b573e2b038ad31d6a141e1d530a9a4f38377ea0523a18a42161
        toRawBuffer() {
            var buf = '';
            // 4 byte: version bytes
            var nVersion = this.private  ? 0x0488ADE4 : 0x0488B21E;
            buf += intTobigEndia32Buffer(nVersion) // mainnet: 0x0488B21E public, 0x0488ADE4 private
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
        // convert sur 58base endoding
        // ex: "xprv9s21ZrQH143K3ZSfMynXEy6nuHq4E2q7Hkoa58hQwRtr2pmuPeNFU3yd7eogz96USc9EtbF4AJuorvMEJPMQdTW2C35YSaPPaD2bn8U4F9V"
        toStringBase58() {
            // encode buffer with CRC in base 58
            var buffer =  this.toRawBuffer();
            return base58CheckEncode( buffer )
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