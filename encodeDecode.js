/**
 ****************************************************** 
 * @file    encodeDecode.js
 * @file    encode and decode from different format
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

/**
 * convert a numbers or a buffer into hexadecimal string.
 * @param   {string,number,bingint} x the value or string/buffer to convert
 * @returns {string} ex : "79BE667EF9DCBBAC5"
 */
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

// caracter set to encode/decde in base58
const sBASE58_CHARSET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const _58 = BigInt(58)

/**
 *  decode a string in base58 ta a binary buffer 
 *
 * @param   {string} base58encoded ex : "xprv9s21ZrQH143K.."
 * @returns {string}               ex : "0488ade4000000000000000000fe0abe524e..."
 */
function base58Decode( base58encoded ) {
    if (base58encoded=="") return "";
    
    //  leading 1 means  "0" in the result buffer
    var nLeading0 = 0;
    while (base58encoded[0]==='1')
        nLeading0++;
    
    var numBuf = BigInt(0)
    for (var i=nLeading0;i<base58encoded.length;i++) {
        // get char <i> and convert it to a number in [0-57]
        var cI = base58encoded[i];
        var n = sBASE58_CHARSET.indexOf(cI);
        // if invalid char
        if (n==-1) {
            //console.assert(false,"invalid base 58 char : " + cI);
            return { error:"invalid base 58 char ", char:cI};
        }
        // calc résul
        numBuf  = numBuf * _58 + BigInt(n)
    }
    // convert numBuf to buffer
    var sBuffeHex = hex_BigInt(numBuf)
    // inssert a 0 in front if odd
    if (sBuffeHex.length % 2 == 1)
        sBuffeHex = "0"+ sBuffeHex
    // insert leading 0
    sBuffeHex = "00".repeat(nLeading0) + sBuffeHex

    return bufferFromHex( sBuffeHex )
}
/**
 *  decode a string in base58 ta a binary buffer with crc
 *
 * @param   {string} base58encoded ex : "xprv9s21ZrQH143K.."
 * @returns {string}        in case on sucess. ex : "0488ade4000000000000000000fe0abe524e..."
 * @returns {object.error}  in case on failure. 
 */
function base58CheckDecode(base58encoded) {
    // decode to raw buffer
    var bufferAndCrc = base58Decode(base58encoded)
    if (bufferAndCrc.error) 
        return bufferAndCrc // failed
    // get resulb
    var nLen = bufferAndCrc.length
    if (nLen<=3)
        return { error:"bad legnth, must be greater than 3", legnth:nLen, source:base58encoded }
    var buffer = bufferAndCrc.substring(0,nLen-4)
    // get crc
    var crc = bufferAndCrc.substring(nLen-4,nLen)
    // calculate crc
    var calcCrc    = sha256(sha256( buffer )).substr(0,4)
    if (calcCrc != crc) 
        return { error:"bad crc", crc:hex(crc), expectedCrc:hex(calcCrc) } // bad crc
    // sucess
    return buffer

}

/**
 *  encode a binary buffer to base58
 *
 * @param   {string} buffer source binairy buffer
 * @returns {string} encoded string. ex : "xprv9s21ZrQH143K"
 */
function base58Encode( buffer, prefix ) {
    if (!prefix)
        prefix = ''

    // convert to hexa
    var hexaBuf= hex(  prefix + buffer )
    // convert to number
    var numBufAndCrc = BigInt( "0x" + hexaBuf )
    // main loop : divive by 58 until numBuf go to 0.
    var res = ""
    
    while (numBufAndCrc>0) {
        var c = Number( numBufAndCrc % _58); // modulo
        // add char in front
        res = sBASE58_CHARSET[c] + res
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
 * 
 * @param   {string} buffer the buuffer to encode. ex : " "0488ade4000000000000000000fe0abe524e..."
 * @returns {string} a base 58 encoded string. ex: ""xprv9s21ZrQH143K..."
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
/**
 * convert a buffer into BigInt assuming the buffer in big endian format 
 * = most significant byte first
 * @param {string} buf 
 * @return {BigInt} 256 bits unsigned big int
 */
function bigInt256FromBigEndianBuffer( buf ) {
    console.assert( typeof buf == "string")

    var result = BigInt(0);
    const _256 = BigInt(256);
    // add 32 bytes = 256 buts
    for (var i=0;i<32;i++) {
        var nI = BigInt(buf.charCodeAt(i)) 
        result = result*_256  + nI
    }
    return result  
}
  
/**
 *  convert a 256 bits BigInt into a big endian buffer of 32 bytes in big endian format.
 * = most significant byte first
 *  @param  {bigInt} x 256 bit number to convert
 *  @return {string} big endian buffer of 32 bytes
 */
function bigEndianBufferFromBigInt256(x) {
    console.assert(typeof x == "bigint")
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

/**
* convert a buffer into int assuming the buffer is in big endian format
* = most significant byte first
* @param {string} buf
* @param {int}    pos 1st char to convert in buf. 0 if non set
*/
function int32FromBigEndianBuffer( buf, pos ) {
    if (!pos) pos= 0;
    var res  =    (buf.charCodeAt(pos  )<<24)
                | (buf.charCodeAt(pos+1)<<16)
                | (buf.charCodeAt(pos+2)<<8 )
                | (buf.charCodeAt(pos+3)    )
    return res  
}
/**
* convert a buffer into int assuming the buffer is in liitle endian format
* = least significant byte first (intel for ex.)
* @param {string} buf
* @param {int}    pos 1st char to convert in buf. 0 if non set
*/
function int32FromLittleEndianBuffer( buf, pos ) {
    if (!pos) pos= 0;
    var res  =    (buf.charCodeAt(pos+3 )<<24)
                | (buf.charCodeAt(pos+2)<<16)
                | (buf.charCodeAt(pos+1)<<8 )
                | (buf.charCodeAt(pos  )    )
    return res  
}

/**
 *  convert a int into a big endian buffer of 4 bytes representing a 32 bits int.
 */
function bigEndianBufferFromInt32(x) {
    var buf =  String.fromCharCode((x>>24) & 0xFF)
        buf += String.fromCharCode((x>>16) & 0xFF)
        buf += String.fromCharCode((x>> 8) & 0xFF)     
        buf += String.fromCharCode( x      & 0xFF)                     
    return buf
}  
/**
 *  convert a int into a little endian buffer of 4 bytes representing a 32 bits int.
 * = least significant byte first (intel for ex.)
 */
function littleEndianBufferFromInt32(x) {
   var buf =  String.fromCharCode (x      & 0xFF)
       buf += String.fromCharCode((x>> 8) & 0xFF)
       buf += String.fromCharCode((x>>16) & 0xFF)     
       buf += String.fromCharCode((x>>24) & 0xFF)                    
   return buf
}  

/**
 *  convert a UI64 into a big endian buffer of 8 bytes representing a 64 bits int.
 * @param  {BigInt} x 64 bits unsiginend number
 * @return {string} 8 bytes buffer
 */
function bigEndianBufferFromUInt64(x) {
    console.assert(x>=0);      
    const _2pow32 =  BigInt("0x100000000");
    var high = Number(x / _2pow32)  
    var low  = Number(x % _2pow32); 
    return bigEndianBufferFromInt32(high) + bigEndianBufferFromInt32(low)
}      
/** 
 * convert a int into a big endian buffer of 8 bytes representing a 128 bits int.
 * @param  {BigInt} x 128 bits unsignend number.
 * @return {string} 16 byte buffer
 */
function bigEndianBufferFromUInt128(x) {
    const _2pow64 =  BigInt("0x100000000000000000");
    var high = (x / _2pow64)  
    var low  = (x % _2pow64);     
    return bigEndianBufferFromUInt64(high) + bigEndianBufferFromUInt64(low)
}   
/** 
 *  convert a buffer into uint64 assuming the buffer in ins big endian
 * = most significant byte first
 * @param  {string} buf 
 * @param  {Number} pos postiion of the 1st char to convert in buf
 * @return {BigInt} 64 bits unsigned int
 */ 
function UInt64FrombigEndianBuffer( buf, pos ) {
    var temp = new BigUint64Array( 1 )
    var nRes = temp[0];
    for (var i=0;i<8;i++) {
        nRes = nRes * BigInt(256);
        nRes += BigInt( buf.charCodeAt(pos+i) );
    }
    return nRes  
}