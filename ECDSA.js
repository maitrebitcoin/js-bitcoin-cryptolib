// Elliptic Curve Signature for Bitcoin
// see :
// https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

// generate cryto secure 256 bits random number
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

// convert a buffer into BigInt assuming the buffer in low endian format
function lowEndianBufferTo256BitInt( buf ) {
    var result = BigInt(0);
    const _256 = BigInt(256);
    // add 32 bytes = 256 buts
    for (var i=0;i<32;i++) {
        var nI = BigInt(buf.charCodeAt(31-i)) 
        result = result*_256  + nI
    }
    return result  
}

// Main class
// ecdsa with secp256k1 parameters
// ex usage :
//    var priv = ecdsa.newPrivateKey();
//    var pub  = ecdsa.publicKeyFormPrivateKey(priv);
//    var signature = ecdsa.signMessage( "my message", priv )
//    var res       = ecdsa.verifySignature( "my message", signature, pub )
//    if (!res.ok) alert(res.message)

class ECDSA { 
// ------ types -----
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
            this.point = point;          
        }
        toString() {
            return hex(this.point.x) + ',' + hex(this.point.y)
        }        
        isZero() {
            return this.point.isZero();
        }
    };
    // represent a signature for ECDSA
    static Signature = class { 
        constructor( r, s ) {
            console.assert( typeof r == 'bigint' )
            console.assert( typeof s == 'bigint' )
            this.r = r
            this.s = s
        }
        toString() {
            return hex(this.r)+':'+ hex(this.s)
        }
    };
    // represente a resul to ECDSA verifySignature    
   static SignatureCheck = class { 
       constructor( ok, message ) {
            this.ok      = ok
            this.message = message
       }
     
   }

// ------ methods -----

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
 *  generate a private key from a hexadecimal string.
 * ex : "0c34cf6a7d24367baa81ef8331c8cb7ffafc0978ff6cf9e5d873de96142bdb86"
 * @returns {ECDSA.PrivateKey}
 */
privateKeyFromHexString( hexString ) {
    console.assert( typeof hexString == 'string' ) 
    console.assert( hexString.length == 64 ) 
    var bigI = BigInt( "0x" + hexString)
    var privateKey = new ECDSA.PrivateKey( bigI );
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
    console.assert( typeof message == 'string' ) 
    // calc message hash
    var hashbuffer    = sha256(sha256( message ));
    // convert to 256 Bits integer
    var h      = lowEndianBufferTo256BitInt(hashbuffer)
    // generate random number k
    // TOOD : deterministic-ECDSA, the value k is HMAC-derived from h + privKey (see RFC 6979)
    var k      = getRandomBigInt256()
    // Calculate the random point R = k * G and take its x-coordinate: r = R.x
    var pointR = this.ec.pointGeneratorScalarMult( k );
    var r      = this.oField.modulo( pointR.x );
    // Calculate the signature proof: s = k^{-1} * (h + r * privKey) mod nk 
    var invK   = this.oField.inversion(k);
    var rpk    = this.oField.mult(   r,     privateKey.value ); // r*privKey
    var h_rpk  = this.oField.add(    h,     rpk );              // h + r*privKey
    var s      = this.oField.mult(   invK,  h_rpk );
    //var minuss = this.oField.negate( s ); //@TODO, use it if < s 
    // create result
    var signature = new ECDSA.Signature( pointR.x, s)
    return signature;

}
/**
 * check a signature 
 * 
 * @param {string} message
 * @param {ECDSA.Signature} signature
 * @param {ECDSA.PublicKey} publicKey
 * @returns {bool}
 */
verifySignature( message, signature, publicKey ) {
    console.assert( typeof message == 'string' ) 
    // sanity checks
    // check public key
    if (publicKey.isZero()) 
        return new ECDSA.SignatureCheck(false, 'invalid public key : 0');
    if (!this.ec.pointOnCurve(publicKey.point))  
        return new ECDSA.SignatureCheck(false, 'invalid public key : not on curve');
    var point0  = this.ec.pointGeneratorScalarMult( this.oField.N );
    if (!point0.isZero)
        return new ECDSA.SignatureCheck(false, 'invalid public key : P*K is not 0');
    //  check signature
    if (signature.r <= 0) 
        return new ECDSA.SignatureCheck(false, 'invalid signature : r is 0');
    if (signature.r >= this.oField.N) 
        return new ECDSA.SignatureCheck(false, 'invalid signature : r is > N');
    if (signature.s <= 0) 
        return new ECDSA.SignatureCheck(false, 'invalid signature : s is 0');
    if (signature.s >= this.oField.N) 
        return new ECDSA.SignatureCheck(false, 'invalid signature : s is > N');

    // calc message hash
    var hashbuffer    = sha256(sha256( message ));
    // convert to 256 Bits integer
    var h      = lowEndianBufferTo256BitInt(hashbuffer)

    // u1 = h * 1/signature.s 
    var invS = this.oField.inversion(signature.s);    
    var u1   = this.oField.mult( h,           invS );
    var u2   = this.oField.mult( signature.r, invS );
    // calculate u1*G + u2*publicKey
    var pt1      =  this.ec.pointGeneratorScalarMult(         u1 )
    var pt2      =  this.ec.pointScalarMult( publicKey.point, u2 )
    var pt1Plus2 =  this.ec.pointAdd(pt1, pt2);
    
    // signature is invalid only if final point is 0
    if (pt1Plus2.isZero())
        return new ECDSA.SignatureCheck(false, 'invalid signature : point is 0');

    // The signature is valid if r=x mod N, invalid otherwise.
    if ( signature.r != pt1Plus2.x )
        return new ECDSA.SignatureCheck(false, 'signature and key does not match');

    // OK
    return new ECDSA.SignatureCheck(true,"OK");
}

};//class ECDSA
