/**
 ****************************************************** 
 * @file    bip39.js
 * @file    Bitcoin bip39 implementation : mnemonic phrase <=> seed for bip32 hdwallet
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * 
 * @license LGPL-3.0 
 ******************************************************
 */


/**
 *  convert a mnemonic pharase to a buffer that can be used as a seed
 * @param {string} mnemonicPhrase UTF-8 NFKD phrase. ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
*  @param {string} password optionnal additional password. 
 * @return {string} 512 bits seed
 */
function bufferFromPhrase(  mnemonicPhrase,  password ) {
    var salt =  "mnemonic"
    if (password)
        salt += password
    return PBKDF2_512( hmac_sha512, mnemonicPhrase,  salt, 2048  )
}

/**
 * 
 * key derivation functions 
 * @see https://en.wikipedia.org/wiki/PBKDF2
 * @param {function} hashFunction * 
 * @param {string} password 
 * @param {string} salt 
 * @param {int} iteration 
 * @return {string} 512 bits buffer
 * 
 */
function PBKDF2_512( hashFunction, password, salt, iteration ) {
    // first iteration
    var U = hashFunction( password, salt + bigEndianBufferFromInt32( 1 )  )
    var F = U;
    for (var i=1;i<iteration;i++) {
        // next ieration 
        U = hashFunction( password, U )
        F = xorBuffer( F, U )
    }
    console.assert(F.length == 64, "T should be 512 bits")
    return F
}

function xorBuffer( buf1, buf2 ) {
    var res = ""
    for (var i=0;i<buf1.length;i++) {
        res += String.fromCharCode( buf1.charCodeAt(i) ^ buf2.charCodeAt(i) )
    }
    return res;
}
