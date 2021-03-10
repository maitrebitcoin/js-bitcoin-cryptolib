/**
 ****************************************************** 
 * @file    bitcoinwallet.js 
 * @file    bitcoin wallet support.
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

// supported  wallet types
const WalletType = {
    // hd wallet
    LEGACY :        "legacy-bip44", // ex : 1HQ9NyviEu5ZZPWz2nCV7NijzAUib9nV4K
    SEGWIT :        "segwit-bip49", // ex : 3EDd9HCf4jY63XJz61PYf1SM9gGzQ3eHjD
    SEGWIT_NATIVE : "segwit-bip84"  // ex : bc1qvejtxv2d50dew625p444cjxdy4su6g8u49mt9t
}

class BitcoinWallet {
/** 
 *   constructor
 * @public
 * @param {WalletType}  [walletType=WalletType.SEGWIT_NATIVE] type of wallet to create. 
 */
constructor(  walletType ) {
    if (!walletType)
        walletType = WalletType.SEGWIT_NATIVE
    this.walletType = walletType;    
    // init derivation path to main account. ex : "m/84'/0'/0'"
    this.mainDerivationPath = this._derivationPathFromType( this.walletType )        
}    
/** 
 *  create a new wallet from the system random generator ( window.crypto.getRandomValues )
 * @public
 */
initFromRandom() {
    // generate a random buffer
    var randomBuffer = this._getRandomBuffer(128)
    // calculate the mnemonic phrase from this buffer
    // ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
    this.phrase      = bip39phraseFromRandomBuffer(randomBuffer)
    // calculate the seed for a bip32 wallet (can be slow)
    var seed         = seedFromPhrase(this.phrase)
    // init the wallet from the seed
    this.initFromSeed(seed,this.walletType)
}
/** 
 *  init the wallet from a seed 
 * @public
 * @param {string}     seed       128 to 512 bits buffer  
 * @param {WalletType} walletType WalletType.LEGACY, WalletType.SEGWIT or WalletType.SEGWIT_NATIVE
 */
initFromSeed(seed ) {
    console.assert( seed.length >= 16 && seed.length <= 64 ,"seed must be between 128 and 512 bits")
 
    // init a hd wallet
    this.hdwallet = new hdwallet(seed, this.walletType )

}
/**
 *  get the extend master key as a string
 * @public
 * @returns {string} the master key. ex "xprv9s21ZrQH143K2H2..."
 */
getMasterKey() {
    if (!this.hdwallet) 
        throw {error:"wallet not initalized."}
    return this.hdwallet.getMasterKey().toStringBase58()
}
/**
 *  get a public bitcoin address
 * @public
 * @param   {int}    [index=0]      index of the child key. 0 is the first accout
 * @param   {bool}   [change=false] is the adress for change ?
 * @returns {string} the bitcoin address. ex : "bc1qn085dr40dcrhejgve4sky.." 
 */
getPublicAddress( index, change ) {
    if (!this.hdwallet) 
        throw {error:"wallet not initalized."}    
    // calculates derivation path
    var derivationPath = this.mainDerivationPath 
    // change or main receveiving ?
    if (change)
        derivationPath+= '/1'
    else
        derivationPath+= '/0'
    // index
    if (!index) index = 0
    derivationPath += "/" + index

    // calculates account
    switch (this.walletType) {
        case WalletType.SEGWIT_NATIVE : return this.getSegwitNativePublicAdressFromPath(derivationPath)
        case WalletType.SEGWIT        : return this.getSegwitPublicAdressFromPath(      derivationPath)
        case WalletType.LEGACY        : return this.getLegacyPublicAdressFromPath(      derivationPath)              
        default:            
            throw {error:"invalid wallet type",walletType:walletType}     
    }
}

/**
 *  get a sewigt native adress 
 *  
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/84'/0'/0'/0/0"
 * @returns {string}  bech 32 address. ex : "bc1qn085dr40dcrhejgve4sky.."      
 * @see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
 */
getSegwitNativePublicAdressFromPath( derivationPath ) {
    // get the extendede public key
    var extPublicKey = this.hdwallet.getExtendedPubliceKeyFromPath(derivationPath);
    if (extPublicKey.error) 
        return extPublicKey; // failed
    console.assert( extPublicKey.publicKey )
    // serialised public key to raw buffer
    var publicKeySerialized = extPublicKey.publicKey.toBuffer();
    // @see https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh
    //      https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    //      https://bitcointalk.org/index.php?topic=4992632.0
    var hashKey            = ripemd160( sha256( publicKeySerialized ) )
    var btcAdress          = bech32Encode( "bc", 0, hashKey );
    return btcAdress
}    
/**
 *  get a sewigt public adress for a derivation path + index. 
 *  
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/49'/0'/0'/0/0"
 * @returns {string}  address. ex : "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX"      
 */
getSegwitPublicAdressFromPath( derivationPath ) {
    // get the extendede public key
    var extPublicKey = this.hdwallet.getExtendedPubliceKeyFromPath(derivationPath );
    if (extPublicKey.error) 
        return extPublicKey; // failed
    console.assert( extPublicKey.publicKey )
    // serialised public key to raw buffer
    var publicKeySerialized = extPublicKey.publicKey.toBuffer();
    // bitcoin P2WPKH format :
    // If the version byte is 0, and the witness program is 20 bytes:
    // It is interpreted as a pay-to-witness-script-hash (P2WSH) program. 
    // NB : OP_HASH160 is ripemd160( sha256( x ) )
    var hashKey            = ripemd160( sha256( publicKeySerialized ) )
    var scriptSig          = '\x00\x14' + hashKey // \x00 : version byte, \x14=20   witness program
    var addressBytes       = ripemd160( sha256( scriptSig)  )       
    var btcAdress          = base58CheckEncode( addressBytes,  PREFIX_P2SH );
    return btcAdress
}
/**
 *  get a legacy public adress for a derivation path + index. 
 *  
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/44'/0'/0'/0/0"
 * @returns {stringy} P2PKH address = legacy format. ex : "1E3B4m6BSw7v2A7TiA2YxDTXBZjFEpBmPN"      
 */
getLegacyPublicAdressFromPath( derivationPath, index ) {
    // get the extendede public key
    var extPublicKey = this.hdwallet.getExtendedPubliceKeyFromPath(derivationPath );
    if (extPublicKey.error) 
        return extPublicKey; // failed
    console.assert( extPublicKey.publicKey )
    // serialised public key to raw buffer
    var publicKeySerialized = extPublicKey.publicKey.toBuffer();
    // legacy bitcoin format :
    var hash               = ripemd160( sha256( publicKeySerialized ) ) 
    var btcAdress          = base58CheckEncode( hash,  PREFIX_P2PKH );
    return btcAdress
}

// get the main derivation path from type
 _derivationPathFromType( walletType ) {
    switch (walletType) {
        case WalletType.LEGACY:        return DerivationPath.LEGACY_BIP44
        case WalletType.SEGWIT:        return DerivationPath.SEWITG_BIP49    
        case WalletType.SEGWIT_NATIVE: return DerivationPath.SW_NATIVE_BIP84      
        default:
            throw {error:"invalid wallet type",walletType:walletType}         
    }
}
// generate a cryto secure random buffer
 _getRandomBuffer( nbBit ) {
    var nbUint32 = nbBit >> 5;
    // get random 32 bits ints
    var randArray = new Uint32Array(nbUint32);
    window.crypto.getRandomValues(randArray);
    // conversion to bigint via hexadecimal string
    var buffer = "";
    for (var i=0;i<nbUint32;i++) { 
        buffer += bigEndianBufferFromInt32( randArray[i] )
    }
    console.assert(buffer.length*8 == nbBit)
    return buffer
}


}

