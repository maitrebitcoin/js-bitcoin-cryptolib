// convert a numbers or a buffer into hexadecimal string.
// mainly for debug/trace purposes

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
