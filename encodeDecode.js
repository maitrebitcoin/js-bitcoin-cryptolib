// js-bitcoin-criptolib
// encode and decode from different format

// convert a numbers or a buffer into hexadecimal string.
function hex( x ){
    switch (typeof  x) {
        case 'bigint':
            return hex_BigInt(x);
        case 'string':
            return hex_buffer(x);
        case 'number':
            return hex_number(x);
        default:
            console.assert( false, "invalid type : " +  typeof  x )
            // retrn undefined
  }
}


// convert a number (int) to hexadecimal string.
// ex: "79BE667E""
function hex_number( num ){
    console.assert( typeof  num == 'number' )
    if (num == 0) return '0';
    // force cast to unsigned int
    var temp    = new Uint32Array( [ num ] )
    num = temp[0]

    var hexResult = ''
    while (num != 0)
    {
        // low 4 bits
        var n =  num & 0x0F; // % 16
        // kex caracters 0-1 or A-F
        var hc 
        if (n>=10)
            hc = String.fromCharCode(87+n) // 97 = 'a', 87 = 97-10
        else
            hc = String.fromCharCode(48+n) // 48 = '0'
        // next 4 bytes
        hexResult = hc + hexResult
        num = num >>> 4; // 16
    }
    console.assert( hexResult != '');
    return hexResult
}

// convert a BigIntbig to hexadecimal string.
// ex: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798""
function hex_BigInt( bigIntNumber ){
    console.assert( typeof  bigIntNumber == 'bigint' )
    if (bigIntNumber == 0) return '0';

    var hexResult = ''
    while (bigIntNumber > 0)
    {
        // low 4 bits
        var n = parseInt( bigIntNumber % BigInt(16) );
        // kex caracters 0-1 or A-F
        var hc 
        if (n>=10)
            hc = String.fromCharCode(87+n) // 97 = 'a', 87 = 97-10
        else
            hc = String.fromCharCode(48+n) // 48 = '0'
        // next 4 bytes
        hexResult = hc + hexResult
        bigIntNumber = bigIntNumber /BigInt(16);
    }
    console.assert( hexResult != '');
    return hexResult
}

// convert a buffer to hexadecimal string.
// ex: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798""
function hex_buffer(str) {
    var hex = '';
    for(var i=0; i<str.length; i++) {
        var c =  str.charCodeAt(i)
        if (c<16)
            hex += "0"+c.toString(16);
        else
            hex += c.toString(16);
    }
    console.assert( hex.length == str.length*2 )
    return hex;
}

// convert an hex string to buffer
// ex: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
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
/**
 *  encode a binary buffer to base58 + crc
 *  ex: 
 *   "0488ade4000000000000000000fe0abe524ea251534fd667216a4ba40bf256f009e27900bf2a2582eaa7b746a5008265670a5e8723f78e0a443e4f67b68d5a368012bbfa5f7503fb6ebbdc404b93"
 *=>"xprv9s21ZrQH143K4b44oYF6VxMLbBroCaDgiWetWXeDHanBdreeF8bQpUndSvNEeaSaRcXfHv5o2MMSD8koExLB3qBc7baLFGB65y39uHsmuEN" 

 * 
 * @param   {string} buffer
 * @returns {string}
 */
function base58CheckEncode( buffer, prefix ) {
    if (!prefix)
        prefix = ''
    // calc crc
    sBufCrc= sha256(sha256( prefix +buffer ))
    // get 4 first bytes
    sCrc = sBufCrc.substring(0,4); 
    // encode un buffer with 4 crc bytes
    return base58Encode( prefix +buffer + sCrc )
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
// convert a int into a big endian buffer of 4 bytes representing a 32 bits int.
function intTobigEndia32Buffer(x) {
    var buf =    String.fromCharCode((x>>24) & 0xFF)
        buf +=   String.fromCharCode((x>>16) & 0xFF)
        buf +=   String.fromCharCode((x>> 8) & 0xFF)     
        buf +=   String.fromCharCode( x      & 0xFF)                   
    
    return buf
}    
// convert a Big int into a big endian buffer of 32 bytes representing a 256 bits int.
function BigInt256ToLowEndianBuffer(x) {
    console.log(typeof x == "bigint")
    var buf = ""
    var _255 = BigInt(0xFF);
    var _8   = BigInt(0x08);
    for (var i=0;i<32;i++) {
         // low 8 bits to buffer    
         var c = Number(x & _255);
         buf = String.fromCharCode(c) + buf
         // next 8 bits
         x = x >> _8;
    }
    console.assert(buf.length == 32)
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