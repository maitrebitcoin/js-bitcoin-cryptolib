/**
 ****************************************************** 
 * @file    ecdsa.js 
 * @file    Elliptic Curve Signature for Bitcoin
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see     https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
   @see     https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
 * 
 * @license LGPL-3.0 
 ******************************************************
 */


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

const DERHeader = {
    HEAD_INT    : "\x02",
    HEAD_STRUCT : "\x30"
};

// Main class
// ecdsa with secp256k1 parameters
// ex usage :
//    var priv = ecdsa.newPrivateKey();
//    var pub  = ecdsa.publicKeyFormPrivateKey(priv);
//    var signature = ecdsa.signMessage( "my message", priv )
//    var res       = ecdsa.verifySignature( "my message", signature, pub )
//    if (!res.ok) alert(res.message)

class ECDSA { 

// constructor
constructor(  ) {
    // ellipical curve
    this.ec = new EllipticCurveSecp256k1();
    // curve order
    this.order   = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    this.gField  = new GField(  this.order )
}

/**
 *  generate a new private key from random generator : window.crypto.getRandomValues()
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
 *  generate a private key from a BigInt.
 * @param   {bigInt} number  ex : 66622949934292052565325515457306921084360285924745542237609076927686267856258n
 * @returns {ECDSA.PrivateKey}
 */
privateKeyFromBigInt( number ) {
    console.assert( typeof number == 'bigint' ) 
    var privateKey = new ECDSA.PrivateKey( number );
    return privateKey
}
/**
 *  generate a private key from a buffer
 * @param   {string} buffer   256 bits big endian format
 * @returns {ECDSA.PrivateKey}
 */
privateKeyFromBuffer( buffer ) {
    console.assert( typeof buffer == 'string' ) 
    console.assert( buffer.length == 32 ) 
    var  number = bigInt256FromBigEndianBuffer( buffer )
    var privateKey = new ECDSA.PrivateKey( number );
    return privateKey
}
/**
 *  import a private key from base58 encoded string (WIF)
 * @param   {string} stringBase58  string in WIF format. ex "5HueCGU8rMjxEXxiPuD5BDk...""
 * @returns {ECDSA.PrivateKey} the imported private key
 * @throws {struct} if <stringBase58> is invalid
 */
privateKeyFromStringBase58( stringBase58 ) {
    console.assert( typeof stringBase58 == 'string' ) 
    console.assert( stringBase58.length == 52 )  
    // decode buffer anbd check crc.
    var buf = base58CheckDecode(stringBase58);
    // check buffer vality
    if (buf.length!=34)
        throw {error:"invalid key length. should be 34", length:buf.length }
    if (buf[0] != PREFIX_PRIVATEKEY)
        throw {error:"invalid key header. should be 05", header:hex(buf[0]) }    
    if (buf[33] != '\x01')
        throw {error:"invalid key format. la byte should be 01", lastbyte:hex(buf[33]) }    
    // convert to bigint
    var bufferBigInt = buf.substr(1,32)
    var number = bigInt256FromBigEndianBuffer( bufferBigInt )
    var privateKey = new ECDSA.PrivateKey( number );
    return privateKey
}

/**
 * get the public key associated to a private key
 * @param  {ECDSA.PrivateKey} privateKey
 * @returns {ECDSA.PublicKey}
 */
publicKeyFromPrivateKey( privateKey ) {
    var point = this.ec.pointScalarMult( this.ec.G, privateKey.value );
    var publicKey = new ECDSA.PublicKey(point);
    return publicKey;
}
/**
 * get the public key from a serialised bufffer. 
 * @param  {string} buffer 33 bytes buffer. ex : "0200359924c406998e91d4063fe078c32825e6ac4dce0395666ed54315afa3312d"
 * @returns {ECDSA.PublicKey}
 * @throws {struct} if <buffer> is invalid
 */
publicKeyFromBuffer( buffer ) {
    if ( buffer.length != 33) {
        throw {error:"buffer must be 33 bytes long.", buffer:hex(buffer) }
    }
    // the 1st byte si 0X02 or 0x03 depending of the parity of y
    // 0x02 for even / x03 for odd 
    if ( buffer[0] != '\x02' && buffer[0] != '\x03'  ) {
        throw {error:"invalid buffer must start with 02 or 03.", buffer:hex(buffer) }
    }    
    var yIsEven = buffer[0] == '\x02'
    // get the x part
    var x = bigInt256FromBigEndianBuffer( buffer.substr(1) )
    // calculates y so that y^2=x^3+7 => y = sqrt( x^3 + 7 )
    var y = this.ec.calculateYFromX( x, yIsEven );
    // init point
    var point     = new ECPoint(x,y);
    console.assert( this.ec.pointOnCurve(point))   

    // init public key  
    var publicKey = new ECDSA.PublicKey(point);
    return publicKey;
}
/**
 * sign a message
 * 
 * @param {string} message
 * @param {ECDSA.PrivateKey} privateKey
 * @param {string,optionnal} "" or "rfc6979" : https://tools.ietf.org/html/rfc6979
 * @returns {ECDSA.Signature}
 */
signMessage( message, privateKey, option ) {
    console.assert( typeof message == 'string' ) 
    // calc message hash
    var hashbuffer    = sha256(sha256( message ));
    // convert to 256 Bits integer
    var h      = bigInt256FromBigEndianBuffer(hashbuffer)
    // generate k
    var k;
    if (option=="rfc6979")
    {
        //  deterministic-ECDSA, the value k is HMAC-derived from h + privKey (see RFC 6979)
        //  https://tools.ietf.org/html/rfc6979
        var hk = hmac_sha256(privateKey, message)
        k = bigInt256FromBigEndianBuffer(hk);
    }
    else {
        // generate random number k
        k = getRandomBigInt256()
    }
    // K must be in [1,N]
    k = this.gField.modulo( k );    
    if (k==0)
        throw {error:"internal error. k is 0"};
    // Calculate the random point R = k * G and take its x-coordinate: r = R.x
    var pointR = this.ec.pointGeneratorScalarMult( k );
    var r      = this.gField.modulo( pointR.x );
    // Calculate the signature proof: s = k^{-1} * (h + r * privKey) mod nk 
    var invK   = this.gField.inversion(k);
    var rpk    = this.gField.mult(   r,     privateKey.value ); // r*privKey
    var h_rpk  = this.gField.add(    h,     rpk );              // h + r*privKey
    var s      = this.gField.mult(   invK,  h_rpk );
    //var minuss = this.oField.negate( s ); //@TODO, use it if < s 
    // create result
    var signature = new ECDSA.Signature( pointR.x, s)
    return signature;
}

/**
 * convert a signature to a DER encoded buffer
 * @param {ECDSA.Signature} signature 
 * @return {string} DER encoded buffer. ex  :"3042021E...."
 * @throws {struct} if <signature> is invalid
 * @see https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format#:~:text=The%20Distinguished%20Encoding%20Rules%20(DER,numbers%20(r%2Cs)%20.
 */
bufferFromSignature( signature ) {
    if (!signature.r) throw {error:"invalid signature : r is missing"}
    if (!signature.s) throw {error:"invalid signature : s is missing"}

    // DER encoding for a big integer
    function _DerEncodeBigInt( val ) {
        const DER_HEADER_INT    = "\x02"; // header byte indicating an integer
        // 32 bytes
        var buffer = bigEndianBufferFromBigInt256( val )
        //  value must be prepended with 0x00 if  first byte is greater than 0x7F
        if ( buffer.charAt(0) > 0x7F )
            buffer ="\x00" + buffer
        var bufLen = String.fromCharCode( buffer.length )
        var res = DERHeader.HEAD_INT + bufLen + buffer
        return res
    }

    // encode R and S 
    var bufferRS = _DerEncodeBigInt( signature.r )
    bufferRS    += _DerEncodeBigInt( signature.s )   
    // encode struct R + S
    return    DERHeader.HEAD_STRUCT                   
            + String.fromCharCode(bufferRS.length) // one byte to encode the length of the following data  
            + bufferRS
}

/**
 * get the signature from a serialised bufffer. 
 * @param {string} buffer 
 * @return {ECDSA.Signature} 
 * @throws {struct} if <buffer> is invalid
 * @TODO -- buffer in DER format :
 * @see https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format#:~:text=The%20Distinguished%20Encoding%20Rules%20(DER,numbers%20(r%2Cs)%20.
 */
signatureFromBuffer( bufferDER ) {
    
    // DER decoding for a big integer
    function _DerDecodeBigInt( buffer, pos ) {   
        // check header
        if (buffer.substr(pos,1) != DERHeader.HEAD_INT ) 
            throw {error:"invalid DER BigInt buffer",  pos:pos, buffer:hex(buffer) }
        var lenR = buffer.charCodeAt(pos+1)
        if (lenR!=0x20 && lenR!=0x21) 
            throw {error:"invalid DER buffer",  pos:1, buffer:hex(buffer) }
        var lenR = buffer.charCodeAt(pos+2)
        if (lenR==0x21) {
            // skip "00"
            pos++
            if (buffer.charCodeAt(pos+3) != 0 ) 
                 throw {error:"invalid DER BigInt buffer. 0 expected",  pos:3, buffer:hex(buffer)}
        }
        var buffer256Bits = buffer.substr(pos+2)        
        // decode 256 bits
        var res = bigInt256FromBigEndianBuffer( buffer.substr(pos+2), pos )
        return { bigint:res, newpos:pos+2+32 }
    }
    const DER_HEADER_STRUCT = "\x30"; // header byte indicating compound structure
    // check buffer
    if (bufferDER.substr(0,1) != DERHeader.HEAD_STRUCT ) 
        throw {error:"invalid DER buffer", pos:0, buffer:hex(bufferDER) }
    var len = bufferDER.charCodeAt(1)
    if (len<60)
        throw {error:"invalid DER buffer", pos:1, buffer:hex(bufferDER) }
    // decode R and S
    var decodeR = _DerDecodeBigInt( bufferDER, 2 )
    var decodeS = _DerDecodeBigInt( bufferDER, decodeR.newpos )
    // build signature
    return new ECDSA.Signature( decodeR.bigint,  decodeS.bigint);
}



/**
 * check a signature 
 * 
 * @param {string} message
 * @param {ECDSA.Signature} signature
 * @param {ECDSA.PublicKey} publicKey
 * @returns {ECDSA.SignatureCheck} struct with .ok and .message
 */
verifySignature( message, signature, publicKey ) {
    console.assert( typeof message == 'string' ) 
    // sanity checks
    // check public key
    if (publicKey.isZero()) 
        return new ECDSA.SignatureCheck(false, 'invalid public key : 0');
    if (!this.ec.pointOnCurve(publicKey.point))  
        return new ECDSA.SignatureCheck(false, 'invalid public key : not on curve');
    var point0  = this.ec.pointGeneratorScalarMult( this.gField.N );
    if (!point0.isZero)
        return new ECDSA.SignatureCheck(false, 'invalid public key : P*K is not 0');
    //  check signature
    if (signature.r <= 0) 
        return new ECDSA.SignatureCheck(false, 'invalid signature : r is 0');
    if (signature.r >= this.gField.N) 
        return new ECDSA.SignatureCheck(false, 'invalid signature : r is > N');
    if (signature.s <= 0) 
        return new ECDSA.SignatureCheck(false, 'invalid signature : s is 0');
    if (signature.s >= this.gField.N) 
        return new ECDSA.SignatureCheck(false, 'invalid signature : s is > N');

    // calc message hash
    var hashbuffer    = sha256(sha256( message ));
    // convert to 256 Bits integer
    var h      = bigInt256FromBigEndianBuffer(hashbuffer)

    // u1 = h * 1/signature.s 
    var invS = this.gField.inversion(signature.s);    
    var u1   = this.gField.mult( h,           invS );
    var u2   = this.gField.mult( signature.r, invS );
    // calculate u1*G + u2*publicKey
    var pt1      =  this.ec.pointGeneratorScalarMult(         u1 )
    var pt2      =  this.ec.pointScalarMult( publicKey.point, u2 )
    var pt1Plus2 =  this.ec.pointAdd(pt1, pt2);
    
    // signature is invalid only if final point is 0
    if (pt1Plus2.isZero())
        return new ECDSA.SignatureCheck(false, 'invalid signature : point is 0');

    // The signature is valid if r=x mod N, invalid otherwise.
    if ( signature.r != pt1Plus2.x )
        return new ECDSA.SignatureCheck(false, 'signature for message does not match public key');

    // OK
    return new ECDSA.SignatureCheck(true,"OK");
}

// ------ types -----
    // represent a private key for ECDSA
    static PrivateKey = class { 
        constructor( bigint ) {
            console.assert( typeof bigint == 'bigint' )
            this.value = bigint;
        }
        toBuffer() {
            return bigEndianBufferFromBigInt256(this.value) 
        }
        // export private key to WIF format
        //@See https://en.bitcoin.it/wiki/Wallet_import_format        
        toStringBase58() {
            return base58CheckEncode(  this.toBuffer() + '\x01', PREFIX_PRIVATEKEY)
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
        isPublicKey() { return true; }
        // for sample purposes
        toString() {
            return hex(this.point.x)+","+hex(this.point.y)
        }
        fromString(s) {
            var tabVal = s.split(",")
            this.point = new ECPoint(0,0);
            this.point.x = new BigInt("0x" + tabVal[0])
            this.point.y = new BigInt("0x" + tabVal[0])
        }
        // convert to a 33 byte buffer (02+x or 03+x)
        toBuffer() {
            return this.point.toBuffer();
        }
        isZero() {
            return this.point.isZero();
        }
    };
    // represents a signature for ECDSA
    static Signature = class { 
        constructor( r, s ) {
            console.assert( typeof r == 'bigint' )
            console.assert( typeof s == 'bigint' )
            this.r = r
            this.s = s
        }
    };
    // represents a result from the ECDSA verifySignature()
    static SignatureCheck = class { 
       constructor( ok, message ) {
            this.ok      = ok
            this.message = message
       }
     
   }//PublicKey

};//class ECDSA
