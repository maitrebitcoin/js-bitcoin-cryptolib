// hdwallet.js
// bip32 bitcoin wallet.
// see :
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

class hdwallet {

// ------ types -----
    // represent a extended key for a hdwallet
    static ExtendedKey = class { 
        constructor( key, chainCode ) {
            console.assert( typeof key == 'bigint' )
            console.assert( typeof chainCode == 'string' )
            console.assert( seed.chainCode == 32,"chainCode must be 256 bits")            
            this.key = key;
            this.chainCode = chainCode;        
        }
        isExtendedKey() {return true;}
    };

// --- methods --------

// construct a new hdwallet from a seed of 512 bytes
constructor( seed ) {
    console.assert( seed.length == 64,"seed must be 512 bits")
    this.seed = seed
    this.ecdsa = new ECDSA();
}

// internal Child key derivation (CKD) functions
_cdk( extendedKey, i ) {
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

    var res = new hdwallet.ExtendedKey( childKey, IR );
    return res;
}


}; // class hdwallet