// Elliptic Curve Signature for Bitcoin
// see :
// https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

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
}

/**
 *  generate a private key
 * @returns {BigInt}
 */
newPrivateKey(  ) {
    // 256 bits = 8 * 32bits
    var randArray = new Uint32Array(8);
    window.crypto.getRandomValues(randArray);
    // conversion to bigint via hexadecimal string
    var bighex = "0x";
    for (var i=0;i<8;i++)
    { 
        bighex += hex( BigInt(randArray[i]) ) ; 
    }
    // conversion to privateKey
    var privateKey = new ECDSA.PrivateKey( BigInt(bighex) );
    return privateKey
}


/**
 * get the public key associated to a private key
 * @param {BigInt} privateKey
 * @returns {ECPoint}
 */
publicKeyFormPrivateKey( privateKey ) {
    var point = this.ec.pointScalarMult( this.ec.G, privateKey.value );
    var publicKey = new ECDSA.PublicKey(point);
    return publicKey;
}


};//ECDSA