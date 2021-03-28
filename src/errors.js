/**
 ****************************************************** 
 * @file    errors.js
 * @file    handling of all the error than can be raised
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

// all possibles errors
const LibErrors = {
    Invalid_mnemonic_phrase_size    : 1,
    Invalid_mnemonic_phrase_word    : 2,
    Invalid_mnemonic_phrase_crc     : 3,
    Invalid_buffer_size             : 4,
    Wallet_not_initialized          : 5,
    Invalid_wallet_type             : 6,
    Invalid_privkey_len             : 7,
    Invalid_privkey_header          : 8,
    Invalid_privkey_format          : 9,
    Invalid_pubkey_format           : 10,
    Invalid_pubkey_header           : 11,
    Invalid_parameter_type          : 12,
    Invalid_signature_buffer        : 13,
    Invalid_base58_char             : 14,
    Invalid_base58_length           : 15,
    Invalid_base58_crc              : 16,
    Invalid_bech32_separator        : 17,
    Invalid_bech32_char             : 18,
    Invalid_bech32_len              : 19,
    Invalid_bech32_crc              : 20,
    Impossible_pubkey_derivation    : 21,
    Invalid_derivation_path         : 22,
    Invalid_extkey_buffer_len       : 23,
    Invalid_extkey_buffer_header    : 24
}
// errors detail
var TabInfoErrors = [
    { id:LibErrors.Invalid_mnemonic_phrase_size, message:"Invalid number of words : valid values are 12,15,18,21 or 24 words" },
    { id:LibErrors.Invalid_mnemonic_phrase_word, message:"Invalid word" },
    { id:LibErrors.Invalid_mnemonic_phrase_crc,  message:"Invalid phrase crc (some words are incorrect or misplaced)" },
    { id:LibErrors.Invalid_buffer_size,          message:"Invalid buffer size"},
    { id:LibErrors.Wallet_not_initialized,       message:"Wallet not initalized"},
    { id:LibErrors.Invalid_wallet_type,          message:"Invalid wallet type"},
    { id:LibErrors.Invalid_privkey_len,          message:"Invalid private key length : should be 34"},
    { id:LibErrors.Invalid_privkey_header,       message:"Invalid private key header : should be 05"},
    { id:LibErrors.Invalid_privkey_format,       message:"Invalid private key format : last byte should be 01"},
    { id:LibErrors.Invalid_pubkey_format,        message:"Invalid public key format : buffer must be 33 bytes long"},
    { id:LibErrors.Invalid_pubkey_header,        message:"Invalid public key header : buffer must start with 02 or 03"},
    { id:LibErrors.Invalid_parameter_type,       message:"Invalid parameter type"},
    { id:LibErrors.Invalid_signature_buffer,     message:"Invalid signature buffer" },
    { id:LibErrors.Invalid_base58_char,          message:"Invalid base 58 char" },
    { id:LibErrors.Invalid_base58_length,        message:"String is too short : it must be greater than 3 caracters" },
    { id:LibErrors.Invalid_base58_crc,           message:"Invalid base 58 string crc (some caracters are incorrect or misplaced)" },
    { id:LibErrors.Invalid_bech32_separator,     message:"Invalid bech32 string : separator not found" },
    { id:LibErrors.Invalid_bech32_char,          message:"Invalid caracter in bech32 string" },
    { id:LibErrors.Invalid_bech32_len,           message:"Invalid bech32 string : too short" },
    { id:LibErrors.Invalid_bech32_crc,           message:"Invalid bech32 string crc (some caracters are incorrect or misplaced)" },
    { id:LibErrors.Impossible_pubkey_derivation, message:"Hardened derivation of a public key is not possible" },
    { id:LibErrors.Invalid_derivation_path,      message:"invalid derivation path format" },
    { id:LibErrors.Invalid_extkey_buffer_len,    message:"Invalid extended key buffer length (must be 78 byte long)" },
    { id:LibErrors.Invalid_extkey_buffer_header, message:"Invalid extended key buffer : unknown version header" }
]

/**
 * Internal function. create an error to be thrown
 * @param {number} id error number. ex : LibErrors.Invalid_mnemonic_phrase_size
 * @param {*} [moreInfo] additional data for the error. 
 */
function _BuildError( id, moreInfo ) {
    // search for error infos from I
    var errorInfo = TabInfoErrors.find(element => element.id == id);
    if (!errorInfo) {
        console.assert(false,"error non found");
    }
    // create error
    var err    = new Error( errorInfo.message );
    err.id     = errorInfo.id
    err.name   = 'js-bitoin-lib error'
    if (moreInfo)
        err.data   = moreInfo;
    return err;
}
