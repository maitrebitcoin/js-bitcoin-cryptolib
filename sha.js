// sha2 implementation for js-bitcoin-cryptolib
// sha2 256 + sha2 512
// see : 
// https://en.wikipedia.org/wiki/SHA-2


// convert a int into a big endian buffer of 4 bytes representing a 32 bits int.
function intTobigEndia32Buffer(x) {
    var buf =    String.fromCharCode((x>>24) & 0xFF)
        buf +=   String.fromCharCode((x>>16) & 0xFF)
        buf +=   String.fromCharCode((x>> 8) & 0xFF)     
        buf +=   String.fromCharCode( x      & 0xFF)                   
    
    return buf
}    

/**
 * hash a buffer using the sha2 256 algoritmh
 * 
 * @param   {binary string} buffer
 * @returns {binary string}
 */
function sha256( buffer ) {

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
            w[i] = adduint32(w[i-16], adduint32( s0 , adduint32( w[i-7] , s1))) //  w[i-16] + s0 + w[i-7] + s1
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

/**
 * hash a buffer using the sha2 512 algoritmh
 * 
 * @param   {binary string} buffer
 * @returns {binary string}
 */
function sha512( buffer ) {
    const _2pow32 =  BigInt("0x100000000");
    // force conveert int to BigInt uin32
    function toBigUI32(x) {
        var temp = new Uint32Array([x])
        return BigInt( temp[0] );
    }

   // right rotate x if bits bits, result forced in unsigned int 642 bits
    function rightrotate64(x, bits) {
        var high = Number(x / _2pow32)  
        var low  = Number(x % _2pow32); 
        if (bits>31) {
            bits -= 32;
            // exchange low and high
            var temp = low;
            low =high;
            high=temp;
        }
        var highR = high >>> bits  |  (low  << (32-bits))
        var lowR  = low  >>> bits  |  (high << (32-bits))
        //result
        var temp    = new BigUint64Array( 1 )
        temp[0] |= toBigUI32( highR ) * _2pow32
        temp[0] |= toBigUI32( lowR ) 
        return   temp[0];
    };
    // right shift x if bits bits
    function rightshift64(x, bits) {
        var high = Number(x / _2pow32)  
        var low  = Number(x % _2pow32); 
        if (bits>31) {
            bits -= 32;
            high =0
            low =high;
        }        
        var highR = high >>> bits  
        var lowR  = low  >>> bits  |  (high << (32-bits))
        //result
        var temp    = new BigUint64Array( 1 )
        temp[0] |= toBigUI32( highR ) * _2pow32
        temp[0] |= toBigUI32( lowR ) 
        return   temp[0];
    };    
    // safe 64 bits addition with overflow ignored
    function adduint64 (x, y) { 
        var temp    = new BigUint64Array( [ x, y ] )
        temp[0] += temp[1];
        console.assert(  temp[0] < BigInt("0x10000000000000000") )
        return temp[0]
    }    
    // convert a UI64 into a big endian buffer of 8 bytes representing a 64 bits int.
    function UI64TobigEndian64Buffer(x) {
        var high = Number(x / _2pow32)  
        var low  = Number(x % _2pow32); 
        return intTobigEndia32Buffer(high) + intTobigEndia32Buffer(low)
    }       
    // convert a int into a big endian buffer of 8 bytes representing a 64 bits int.
    function intTobigEndian128Buffer(x) {
        return "\x00".repeat(12) + intTobigEndia32Buffer(x)
    }   
    // convert a buffer into uint64 assuming the buffer in ins big endian
    function bigEndianBufferToUI64( buf, pos ) {
        var temp = new BigUint64Array( 1 )
        var nRes = temp[0];
        for (var i=0;i<8;i++) {
            nRes = nRes * BigInt(256);
            nRes += BigInt( buf.charCodeAt(pos+i) );
        }
        return nRes  
    }

    // sha2 constants :
    //  (first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    var H    = new BigUint64Array( ["0x6a09e667f3bcc908", "0xbb67ae8584caa73b", "0x3c6ef372fe94f82b", "0xa54ff53a5f1d36f1", 
                                    "0x510e527fade682d1", "0x9b05688c2b3e6c1f", "0x1f83d9abfb41bd6b", "0x5be0cd19137e2179" ] );     
    //  (first 64 bits of the fractional parts of the cube roots of the first 64 primes 2..311): 
    var K    = new BigUint64Array( ["0x428a2f98d728ae22", "0x7137449123ef65cd", "0xb5c0fbcfec4d3b2f", "0xe9b5dba58189dbbc", "0x3956c25bf348b538", 
                                    "0x59f111f1b605d019", "0x923f82a4af194f9b", "0xab1c5ed5da6d8118", "0xd807aa98a3030242", "0x12835b0145706fbe", 
                                    "0x243185be4ee4b28c", "0x550c7dc3d5ffb4e2", "0x72be5d74f27b896f", "0x80deb1fe3b1696b1", "0x9bdc06a725c71235", 
                                    "0xc19bf174cf692694", "0xe49b69c19ef14ad2", "0xefbe4786384f25e3", "0x0fc19dc68b8cd5b5", "0x240ca1cc77ac9c65", 
                                    "0x2de92c6f592b0275", "0x4a7484aa6ea6e483", "0x5cb0a9dcbd41fbd4", "0x76f988da831153b5", "0x983e5152ee66dfab", 
                                    "0xa831c66d2db43210", "0xb00327c898fb213f", "0xbf597fc7beef0ee4", "0xc6e00bf33da88fc2", "0xd5a79147930aa725", 
                                    "0x06ca6351e003826f", "0x142929670a0e6e70", "0x27b70a8546d22ffc", "0x2e1b21385c26c926", "0x4d2c6dfc5ac42aed", 
                                    "0x53380d139d95b3df", "0x650a73548baf63de", "0x766a0abb3c77b2a8", "0x81c2c92e47edaee6", "0x92722c851482353b", 
                                    "0xa2bfe8a14cf10364", "0xa81a664bbc423001", "0xc24b8b70d0f89791", "0xc76c51a30654be30", "0xd192e819d6ef5218", 
                                    "0xd69906245565a910", "0xf40e35855771202a", "0x106aa07032bbd1b8", "0x19a4c116b8d2d0c8", "0x1e376c085141ab53", 
                                    "0x2748774cdf8eeb99", "0x34b0bcb5e19b48a8", "0x391c0cb3c5c95a63", "0x4ed8aa4ae3418acb", "0x5b9cca4f7763e373", 
                                    "0x682e6ff3d6b2b8a3", "0x748f82ee5defb2fc", "0x78a5636f43172f60", "0x84c87814a1f0ab72", "0x8cc702081a6439ec", 
                                    "0x90befffa23631e28", "0xa4506cebde82bde9", "0xbef9a3f7b2c67915", "0xc67178f2e372532b", "0xca273eceea26619c", 
                                    "0xd186b8c721c0c207", "0xeada7dd6cde0eb1e", "0xf57d4f7fee6ed178", "0x06f067aa72176fba", "0x0a637dc5a2c898a6", 
                                    "0x113f9804bef90dae", "0x1b710b35131c471b", "0x28db77f523047d84", "0x32caab7b40c72493", "0x3c9ebe0a15c9bebc", 
                                    "0x431d67c49c100d4c", "0x4cc5d4becb3e42b6", "0x597f299cfc657e2a", "0x5fcb6fab3ad6faec", "0x6c44198c4a475817" ] )

    // message length in bits
    var L  = buffer.length * 8
    // Pre-processing (Padding):
    // begin with the original message of length L bits
    // append a single '1' bit
    buffer += '\x80' // Append 1 bit plus zero padding
    // append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 128 is a multiple of 1024
    var n0Padding = 128 - (buffer.length + 16) % 128;
    if (n0Padding == 128) n0Padding = 0;
    buffer += '\x00'.repeat(n0Padding)
    //append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 128 bytest (1024 bits)
    buffer +=  intTobigEndian128Buffer(L)
    console.assert( buffer.length % 128 == 0)
  
    // Process the message in successive 128 bytes chunks (1024 bits):   
    var nbBlock = buffer.length / 128;
    for (var ibloc=0;ibloc<nbBlock;ibloc++) {
        // extract the 128 bytes bloc
        blockI = buffer.substring( ibloc*128, (ibloc+1)*128 )

        // create a 80-entry message schedule array w[0..63] of 32-bit words
        // (The initial values in w[0..63] don't matter, so many implementations zero them here)
        //var buf64 = new ArrayBuffer( 64 );
        var w = new BigUint64Array(80);

        // copy chunk into first 16 qwords w[0..15] of the message schedule array
        for (var i = 0; i < 16; i++) {
            w[i] = bigEndianBufferToUI64(blockI, i*8)
        }
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
        for (var i = 16; i< 80; i++) {
            var s0 = rightrotate64(w[i-15], 1) ^ rightrotate64(w[i-15], 8) ^ rightshift64(w[i-15], 7)
            var s1 = rightrotate64(w[i- 2],19) ^ rightrotate64(w[i- 2],61) ^ rightshift64(w[i- 2], 6)
            // set result
            w[i] = adduint64(w[i-16], adduint64( s0 , adduint64( w[i-7] , s1))) //  w[i-16] + s0 + w[i-7] + s1
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
        for (var i = 0; i < 80; i++) {
            var S1     = rightrotate64(e, 14) ^ rightrotate64(e,18) ^ rightrotate64(e, 41)            
            var ch     = (e & f) ^ ((~e) & g)
            var temp1  = adduint64(h, adduint64( S1, adduint64(ch , adduint64( K[i] , w[i] )))) // = h + S1 + ch + k[i] + w[i]
            var S0    = rightrotate64(a, 28) ^ rightrotate64(a,34) ^ rightrotate64(a,39)
            var maj    = (a & b) ^ (a & c) ^ (b & c)
            var temp2  = adduint64(S0 , maj)
            
            h = g
            g = f
            f = e
            e = adduint64(d , temp1 )
            d = c
            c = b
            b = a
            a = adduint64(temp1 , temp2 )
        }// main loop

        //Add the compressed chunk to the current hash value:
        H[0] = adduint64(H[0] , a)
        H[1] = adduint64(H[1] , b)
        H[2] = adduint64(H[2] , c)
        H[3] = adduint64(H[3] , d)
        H[4] = adduint64(H[4] , e)  
        H[5] = adduint64(H[5] , f)
        H[6] = adduint64(H[6] , g)
        H[7] = adduint64(H[7] , h)

    } //    for (var ibloc=i;ibloc<nbBlock;ibloc++) 

    // result converted into a string buffer
    var digest = "";
    for (var i = 0; i < 8; i++) { 
        digest += UI64TobigEndian64Buffer( H[i] )
    }
    // result must be 512 bytes long
    console.assert( digest.length == 64)
    return digest;

}//function sha256( buffer  )

// XOR each byte of a buffer
function xorBuffer( bufA, bufB ) {
    console.assert( bufA.length == bufB.length )
    var res='';
    for (var i=0;i<bufA.length;i++) {
        // c = a xor b
        var c = bufA.charCodeAt(i) ^ bufB.charCodeAt(i)
        res += String.fromCharCode(c)
    }
    console.assert( res.length == bufB.length )
    return res
}

// HMAC function
// source https://en.wikipedia.org/wiki/HMAC
function hmac( key, message, hash, blocksize, outpusize ) {

    // Keys longer than blockSize are shortened by hashing them
    if (key.length > blocksize) 
        key = hash(key) // key is outputSize bytes long
    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (key.length < blocksize) {
        // Pad key with zeros to make it blockSize bytes long
        var n0Padding = blocksize -key.length
        key   += '\x00'.repeat(  n0Padding );
    }

    var o_key_pad = xorBuffer( key, '\x5c'.repeat(blocksize))
    var i_key_pad = xorBuffer( key, '\x36'.repeat(blocksize))

    return hash(o_key_pad + hash(i_key_pad + message))
}

/**
 * hash a mssage + key using the hmac-sha-512 algoritmh
 * 
 * @param   {key string}  buffer
 *  @param  {key message} buffer
 * @returns {binary string}
 */
function hmac_sha512( key, message ) {
    // blocksize = 1024/8 => 128 
    var hash =  hmac( key,message, sha512, 128, 64 )
    console.assert( hash.length == 64 )    
    return hash
}
