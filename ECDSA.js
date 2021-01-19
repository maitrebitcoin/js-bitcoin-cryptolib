// Elliptic Curve Signature for Bitcoin
// see :
// https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

// generate a 256 bits random number
function getRandomBigInt256() {
    // 256 bits = 8 * 32bits
    var randArray = new Uint32Array(8);
    window.crypto.getRandomValues(randArray);
    // conversion to bigint via hexadecimal string
    var bighex = "0x";
    for (var i=0;i<8;i++) { 
        bighex += hex( BigInt(randArray[i]) ) ; 
    }
    // conversion to BigInt
    return BigInt(bighex);
}

// convert a buffer into BigInt assuming the buffer in big endian
function bigEndianBufferTo256BitInt( buf ) {
    var result = BigInt(0);
    const _256 = BigInt(256);
    // add 32 bytes = 256 buts
    for (var i=0;i<32;i++) {
        var nI = BigInt(buf.charCodeAt(i)) 
        result = result*_256  + nI
    }
    return result  
}


class ECDSA { 
    // represent a private key for ECDSA
    static PrivateKey = class { 
        constructor( bigint ) {
            console.assert( typeof bigint == 'bigint' )
            this.value = bigint;
        }
        toString() {
            return hex(this.value)
        }
    };

    // represent a public key for ECDSA
    static PublicKey = class { 
        constructor( point ) {
            console.assert( typeof point == 'object' )           
            console.assert(  point.x )       
            console.assert(  point.y )               
            this.value = point;          
        }
        toString() {
            return hex(this.value.x) + '\n<br>' + hex(this.value.y)
        }        
    };


// constructor
constructor(  ) {
    // ellipical curve
    this.ec = new EllipticCurveSecp256k1();
    // curve order
    this.order   = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    this.oField  = new GFied(  this.order )
}

/**
 *  generate a private key
 * @returns {ECDSA.PrivateKey}
 */
newPrivateKey(  ) {
    // get 256 bits random number
    var rand256 =getRandomBigInt256()
    // conversion to privateKey
    var privateKey = new ECDSA.PrivateKey( rand256 );
    return privateKey
}


/**
 * get the public key associated to a private key
 * @param {ECDSA.PrivateKey} privateKey
 * @returns {ECDSA.PublicKey}
 */
publicKeyFormPrivateKey( privateKey ) {
    var point = this.ec.pointScalarMult( this.ec.G, privateKey.value );
    var publicKey = new ECDSA.PublicKey(point);
    return publicKey;
}

 
/**
 * sign a message
 * 
 * @param {string} message
 * @param {ECDSA.PrivateKey} privateKey
 * @returns {ECDSA.Signature}
 */
signMessage( message, privateKey ) {
    // calc message hash
    var hashbuffer    = sha256(sha256( message ));
    // convert to 256 Bits integer
    var h      = bigEndianBufferTo256BitInt(hashbuffer)
    // generate random number k
    var k       = getRandomBigInt256()
    // Calculate the random point R = k * G and take its x-coordinate: r = R.x
    var pointR  = this.ec.pointScalarMult( this.ec.G, k );
    var r       = pointR.x;
    // Calculate the signature proof: s = k^{-1} * (h + r * privKey) mod nk 
    var invK = this.oField.inversion(k);
    var rpk  = this.oField.mult( r,     privateKey.value );
    var h_rpk= this.oField.add(  h,     rpk );
    var s    = this.oField.mult( invK,  h_rpk );

    var signature = {};
    signature.r = pointR.x
    signature.s = s
    return signature;

}


};//ECDSA