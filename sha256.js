// sha2 implementation for js-bitcoin-cryptolib
// see : 
// https://en.wikipedia.org/wiki/SHA-2

/**
 * hash a buffer using the sha2 algoritmh
 * 
 * @param   {binary string} buffer
 * @returns {binary string}
 */
function sha256( buffer ) {
    // sha2 constants :
    //  (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    var H    = new Uint32Array( [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ] );     
    //  (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311): 
    var K    = new Array(   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ) 

    // right rotate x if bits bits, result forced in unsigned int 32 bits
    function rightrotate(x, bits) {
        var temp    = new Uint32Array( [ x  ] )
        temp[0]  = ( temp[0]>>>bits ) | ( temp[0]<<(32 - bits))
        return   temp[0];
    };
    // right shift x if bits bits
    function rightshift(x, bits) {
        return (x>>>bits) 
    };    
    // safe 32 bits addition with overflow ignored
    function adduint32 (x, y) { 
        var temp    = new Uint32Array( [ x, y ] )
        temp[0] += temp[1];
        return temp[0]
    }    
    // convert a int into a big endian buffer of 4 bytes representing a 32 bits int.
    function intTobigEndia32Buffer(x) {
        var buf =    String.fromCharCode((x>>24) & 0xFF)
            buf +=   String.fromCharCode((x>>16) & 0xFF)
            buf +=   String.fromCharCode((x>> 8) & 0xFF)     
            buf +=   String.fromCharCode( x      & 0xFF)                   
     
        return buf
    }    
    // convert a int into a big endian buffer of 8 bytes representing a 64 bits int.
    function intTobigEndian64Buffer(x) {
        return "\x00".repeat(4) + intTobigEndia32Buffer(x)
    }   
    // convert a buffer into int assuming the buffer in ins big endian
    function bigEndianBufferToInt( buf, pos ) {
        var nRes = (buf.charCodeAt(pos)  <<24)
                 | (buf.charCodeAt(pos+1)<<16)
                 | (buf.charCodeAt(pos+2)<<8)
                 | (buf.charCodeAt(pos+3))
        return nRes  
    }

    // message length in bits
    var L  = buffer.length * 8
    // Pre-processing (Padding):
    // begin with the original message of length L bits
    // append a single '1' bit
    buffer += '\x80' // Append 1 bit plus zero padding
    // append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
    var n0Padding = 64 - (buffer.length + 8) % 64;
    if (n0Padding == 64) n0Padding = 0;
    buffer += '\x00'.repeat(n0Padding)
    //append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 64 bytest (512 bits)
    buffer +=  intTobigEndian64Buffer(L)
    console.assert( buffer.length % 64 == 0)
  
    // Process the message in successive 64 bytes chunks:   
    var nbBlock = buffer.length / 64;
    for (var ibloc=0;ibloc<nbBlock;ibloc++) {
        // extract the 64 bytes bloc
        blockI = buffer.substring( ibloc*64, (ibloc+1)*64 )

        // create a 64-entry message schedule array w[0..63] of 32-bit words
        // (The initial values in w[0..63] don't matter, so many implementations zero them here)
        //var buf64 = new ArrayBuffer( 64 );
        var w = new Uint32Array(64);

        // copy chunk into first 16 words w[0..15] of the message schedule array
        for (var i = 0; i < 16; i++) {
            w[i] = bigEndianBufferToInt(blockI, i*4)
        }
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for (var i = 16; i< 64; i++) {
            var s0 = rightrotate(w[i-15], 7) ^ rightrotate(w[i-15],18) ^ rightshift(w[i-15], 3)
            var s1 = rightrotate(w[i- 2],17) ^ rightrotate(w[i- 2],19) ^ rightshift(w[i- 2],10)
            // set result
            w[i] = adduint32(w[i-16], adduint32( s0 , adduint32( w[i-7] , adduint32( s1)))) //  w[i-16] + s0 + w[i-7] + s1
        }
    
        //Initialize working variables to current hash value:
        var a = H[0]
        var b = H[1]
        var c = H[2]
        var d = H[3]
        var e = H[4]
        var f = H[5]
        var g = H[6]
        var h = H[7]

         //   Compression function main loop:
        for (var i = 0; i < 64; i++) {
            var S1     = rightrotate(e, 6) ^ rightrotate(e,11) ^ rightrotate(e,25)
            var ch     = (e & f) ^ ((~e) & g)
            var temp1  = adduint32(h, adduint32( S1, adduint32(ch , adduint32( K[i] , w[i] )))) // = h + S1 + ch + k[i] + w[i]
            var S0     = rightrotate(a, 2) ^ rightrotate(a,13) ^ rightrotate(a,22)
            var maj    = (a & b) ^ (a & c) ^ (b & c)
            var temp2  = adduint32(S0 , maj)
            
            h = g
            g = f
            f = e
            e = adduint32(d , temp1 )
            d = c
            c = b
            b = a
            a = adduint32(temp1 , temp2 )
        }// main loop

        //Add the compressed chunk to the current hash value:
        H[0] = adduint32(H[0] , a)
        H[1] = adduint32(H[1] , b)
        H[2] = adduint32(H[2] , c)
        H[3] = adduint32(H[3] , d)
        H[4] = adduint32(H[4] , e)  
        H[5] = adduint32(H[5] , f)
        H[6] = adduint32(H[6] , g)
        H[7] = adduint32(H[7] , h)

    } //    for (var ibloc=i;ibloc<nbBlock;ibloc++) 

    //result converted to string buffer
    //var b2 = new Uint8Array(H.buffer,0,32);
    var digest = "";
    for (var i = 0; i < 8; i++) { 
        digest += intTobigEndia32Buffer( H[i] )
    }
    console.assert( digest.length == 32)
    return digest;

}//function sha256( buffer  )


