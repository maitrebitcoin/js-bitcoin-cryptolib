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
// knonw prefix
const PREFIX_P2PKH =          "\x00"  //  ex : 17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem
const PREFIX_P2SH =           "\x05"  //  ex : 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
const PREFIX_PRIVATEKEY =     "\x80"  //  ex : 5Hwgr3u458GLafKBgxtssHSPqJnYoGrSzgQsPwLFhLNYskDPyyA

/**
 *  decode a string in base58 ta a binary buffer 
 *
 * @param   {string} base58encoded ex : "xprv9s21ZrQH143K.."
 * @returns {string}               ex : "0488ade4000000000000000000fe0abe524e..."
 * @throws  {struct} if <base58encoded> is invalid
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
        // error if invalid char
        if (n==-1) {
            throw { error:"invalid base 58 char ", char:cI, pos:n};
        }
        // calc résult
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
 * @param   {string} base58encoded   ex : "xprv9s21ZrQH143K.."
 * @returns {string} decoded buffer. ex : "0488ade4000000000000000000fe0abe524e..."
 * @throws  {struct} if <base58encoded> is invalid
 */
function base58CheckDecode(base58encoded) {
    // decode to raw buffer
    var bufferAndCrc = base58Decode(base58encoded)
    // check buffer validity
    var nLen = bufferAndCrc.length
    if (nLen<=3)
        throw { error:"bad legnth, must be greater than 3", legnth:nLen, source:base58encoded }
    var buffer = bufferAndCrc.substring(0,nLen-4)
    // get crc
    var crc = bufferAndCrc.substring(nLen-4,nLen)
    // calculate crc
    var calcCrc    = sha256(sha256( buffer )).substr(0,4)
    if (calcCrc != crc) 
        throw { error:"bad crc", calculatedCrc:hex(crc), expectedCrc:hex(calcCrc) } 
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
    // encode of "" returns ""
    if (prefix+buffer=="")
        return ""
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

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/**
 *  decode a bech32 string into a binary buffer
 * 
 * @param   {string} bench32string string to decode. ex "bc1qw508d6qejxtdg4y5r3zar..."
 * @returns {struct.prefix}  prefix wihtout the "1" separator. ex : "bc"
 * @returns {struct.version} version version number. from 0 to 31
 * @returns {struct.buffer}  data
 * @throws  {struct.error} if <bench32string> is invalid
 * 
 * reference :
 * @see https://en.bitcoin.it/wiki/BIP_0173
 */
function bech32Decode( bench32string  ) {
    var result={};
    // extract prefix
    var posSeparator = bench32string.search('1')
    if (posSeparator<=0) 
        throw {error:"Invalid bench32 string : separator not found", string:bench32string}
    // "bc1qw508d6.." => "bc"
    result.prefix = bench32string.substr(0,posSeparator)
    // "bc1qw508d6.." => "w508d6.."
    var bech32data =  bench32string.substr(posSeparator+1)
    // convert data to an arry of 5bits integers
    var tab5BitValues = []
    for (const charI of bech32data)  { 
        var valueI = BECH32_CHARSET.search(charI);
        if (valueI==-1)
            throw {error:"Invalid bench32 string : bad char", char:charI}
        tab5BitValues.push( valueI )
    } 
    // must hase at least 6 elements : +1 version, +6 checksum
    if (tab5BitValues.length<7)
        throw {error:"Invalid bench32 string : no enougth data", string:bench32string}
    // the 1st int is the version number
    result.version = tab5BitValues[0];
    // calc checksum = array if 6 * 5bits integers
    var tabData         = tab5BitValues.slice(0,tab5BitValues.length-6) 
    var tabChecksum     = tab5BitValues.slice(tab5BitValues.length-6) 
    var tabCalcChecksum = _bech32_create_checksum ( result.prefix, tabData )
    // check 
    for (var i=0;i<6;i++) {
        if (tabChecksum[i] != tabCalcChecksum[i])
            throw {error:"Invalid bench32 string : bad checksum", string:bench32string}
    }
    // calc data
    var resBuffer=""
    var nPosBit= 0;
    for (var i=1;i<tabData.length;i++) { 
        resBuffer = _add5Bit( resBuffer, nPosBit, tabData[i]  )
        nPosBit  += 5 
    }
    result.buffer = resBuffer.substring(0, resBuffer.length-1 );
    return result;

//---------------------------
    // internal func : add 5 bits at pos <numBit> in buffer <buf>. 
    function _add5Bit( buf, numBit, value ) {
        var posInByte =  (numBit/8)>>>0
        // get current value
        var val16Bit  = int16FromBigEndianBuffer(buf, posInByte )
        // add 5 bits
        var pos  = numBit % 8 
        val16Bit = val16Bit | (value << (11-pos))
        // calc final buffer
        buf = buf.substr(0,posInByte)
        buf += String.fromCharCode( (val16Bit&0xFF00)>>>8 );
        buf += String.fromCharCode( (val16Bit&0x00FF) ); 
        return buf
    }
}   

/**
 *  encode a binary buffer to bech32 + crc
 * 
 * @param   {string} prefix prefix wihtout the "1" separator. ex : "bc"
 * @param   {string} version version number. from 0 to 31
 * @param   {string} buffer the buffer to encode. ex : "0279be667ef9dcbb.."
 * @returns {string} a bench32 encoded string. ex: "bc1qw508d6qejxtd..."
 * 
 * reference :
 * @see https://bitcointalk.org/index.php?topic=4992632.0
 * @see https://en.bitcoin.it/wiki/BIP_0173
 * @see https://slowli.github.io/bech32-buffer/
 */
function bech32Encode( prefix, version, buffer  ) {
    console.assert(version >=  0);
    console.assert(version <= 31);

    var tab5BitValues = []

    // version : 5 bits
    tab5BitValues.push(version)    

    // split buffer to an aray ou 5 bit integers
    for (var numbit=0;numbit<buffer.length*8;numbit+=5) {
        tab5BitValues.push( _get5Bit( buffer, numbit ) )
    }
    // add 30 bit checksum = aray if 6 * 5bits int
    var tabChecksum = _bech32_create_checksum ( prefix, tab5BitValues )
    tab5BitValues = tab5BitValues.concat(tabChecksum)
    
    // convert to string with prefix
    var result = prefix  + "1";
    tab5BitValues.forEach(element => {
        result += BECH32_CHARSET[element] 
    });
    return result

    // ---- internal functions ------

    /**
        get 5 bits from a binray buffer at pos <nBit>
     *  @param {string} buf binary buffer
     *  @param {int} nBit bit number in the vuffer
     *  @return{int} a 5 bits integers 
     */
    function _get5Bit( buf, numBit ) {
        var val16Bit = int16FromBigEndianBuffer(buf, numBit/8 )
        var pos     = numBit % 8 
        return ((val16Bit << pos) & 0xF800) >>> 11;
    }

}

/** calc cheksum :
 * @private
 *  @param {string} prefix human readable prefix. ex "bc"
 *  @param {array}  tabVal array of 5 bits integers
 *  @return {array} array of 5 bits integers with 6 entrie
 */
function _bech32_create_checksum( prefix, tabVal ) {  
    var tabPrefix  = _bech32_hrp_expand(prefix) 
    var values = tabPrefix.concat( tabVal )
        values = values.concat( [0,0,0,0,0,0]  )
    polymod = _bech32_polymod(values) ^ 1
    var checksum= []
    for (var i=0;i<6;i++)
        checksum[i] = (polymod >> 5 * (5-i)) & 31;
    return checksum;
}        
function _bech32_polymod(tabVal) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1
    tabVal.forEach(value => {
        var b = (chk >>> 25)
        chk = (chk & 0x1ffffff) << 5 ^ value
        for (var i=0;i<5;i++) {
            // if bit number <i> is set, xor with GEN[i]
            if (((b >> i) & 1) == 1)
                chk ^= GEN[i];
        }
    });
    return chk;
}
// return a array of 5 bits integers
function _bech32_hrp_expand(text) {
    var res = []
    for (const charI of text) { 
        res.push( (charI.charCodeAt(0) >> 5)) 
    }
    res.push(0)
    for (const charI of text)  { 
        res.push( (charI.charCodeAt(0) & 31))
    }
    return res
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
* convert a buffer into 32 bit int assuming the buffer is in liitle endian format
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
* convert a buffer into 16 bits int assuming the buffer is in little endian format
* = least significant byte first (intel for ex.)
* @param {string} buf
* @param {int}    pos 1st char to convert in buf. 0 if not set
*/
function int16FromLittleEndianBuffer( buf, pos ) {
    if (!pos) pos= 0;
    var res  =    (buf.charCodeAt(pos+1)<<8 )
                | (buf.charCodeAt(pos  )    )
    return res  
}
/**
* convert a buffer into 16 bits int assuming the buffer is in big endian format
*
* @param {string} buf
* @param {int}    pos 1st char to convert in buf. 0 if not set
*/
function int16FromBigEndianBuffer( buf, pos ) {
    if (!pos) pos= 0;
    var res  =    (buf.charCodeAt(pos  )<<8 )
                | (buf.charCodeAt(pos+1)    )
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
 *  convert a UI64 into a little endian buffer of 8 bytes representing a 64 bits int.
 * = least significant byte first (intel for ex.)
 * @param  {BigInt} x 64 bits unsiginend number
 * @return {string} 8 bytes buffer
 */
function littleEndianBufferFromUInt64(x) {
    console.assert(x>=0);      
    const _2pow32 =  BigInt("0x100000000");
    var high = Number(x / _2pow32)  
    var low  = Number(x % _2pow32); 
    return littleEndianBufferFromInt32(low) + littleEndianBufferFromInt32(high) 
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
