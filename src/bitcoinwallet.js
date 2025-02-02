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
 * @param {number}     nbWord     number of words. 12 to 24.
 */
initFromRandom(nbWord,password='') {
    // calculate the number of bits form the number of words
    if (!nbWord) nbWord= 12;
    var nbBitEntropy = 128;
    switch (nbWord) {
        case 12: nbBitEntropy = 128; break;
        case 15: nbBitEntropy = 160; break;
        case 18: nbBitEntropy = 192; break;
        case 21: nbBitEntropy = 224; break;        
        case 24: nbBitEntropy = 256; break;  
        default:
            throw {error:"Invalid number of words.\n Valid values are 12,15,18,21 or 24 words", nbWord:nbWord }
    }

    // generate a random buffer
    var randomBuffer = this.getRandomBuffer(nbBitEntropy)
    // calculate the mnemonic phrase from this buffer
    // ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
    this.phrase      = bip39phraseFromRandomBuffer(randomBuffer)
    // calculate the seed for a bip32 wallet (can be slow)
    var seed         = seedFromPhrase(this.phrase,password)
    // init the wallet from the seed
    this.initFromSeed(seed,this.walletType)
}
/** 
 *  init the wallet from a menmonic phase and an optionnal password 
 * @public
 * @param {string} phrase    12 to 24 words. ex :"situate before sell found usage useful caution banner stem autumn decrease melt"
 * @param {string} [password] optionnal additional password. 
 * @throws {Error} if <mnemonicPhrase> is invalid
 */
initFromMnemonicPhrase(phrase,password ) {
    console.assert(typeof phrase == 'string')
    // check if the phrase is valid, trow an Error if not
    checkPhrase(phrase)
    // convert to seed
    var seed = seedFromPhrase( phrase, password)
    console.assert( seed.length >= 16 && seed.length <= 64 ,"seed must be between 128 and 512 bits")
    // init a hd wallet
    this.HdWallet = new HdWallet()
    this.HdWallet.initFromSeed (seed, this.walletType )
}
/** 
 *  init the wallet from a seed 
 * @public
 * @param {string}     seed       128 to 512 bits buffer  
 */
initFromSeed(seed ) {
    console.assert( seed.length >= 16 && seed.length <= 64 ,"seed must be between 128 and 512 bits")
 
    // init a hd wallet
    this.HdWallet = new HdWallet()
    this.HdWallet.initFromSeed (seed, this.walletType )
}
/** 
 *  init the wallet from an extended key/  ex : "zpub6sAxdNfDsummUgnQ7y.." 
 * @public
 * @param {string}     extKey58   extended public or private key in base 58 format. ex : "zpub6sAxdNfDsummUgnQ7y.." 
 * @throws {Error}
 */
initFromExtendedKey( extKey58 ) {
     
    // init a hd wallet
    this.HdWallet = new HdWallet()
    this.HdWallet.initFromExtendedKey( extKey58 )
    // copy walley type
    this.walletType = this.HdWallet.walletType
    // re-init derivation path to main account. ex : "m/84'/0'/0'"
    this.mainDerivationPath = this._derivationPathFromType( this.walletType )        
}
/**
 *  get the extend master key as a string
 * @public
 * @returns {string} the master key. ex "xprv9s21ZrQH143K2H2..."
 * @throws  {Error} if the wallet is non initialised
 */
getMasterKey() {
    if (!this.HdWallet) 
        throw _BuildError( LibErrors.Wallet_not_initialized )
    return this.HdWallet.getMasterKey().toStringBase58()
}
/**
 *  get a public bitcoin address. ex : "bc1qn085dr40dcrhejgve4sky.." 
 * 
 * @public
 * @param  {number}  [index=0]      index of the child key. 0 is the first accout
 * @param  {boolean} [change=false] is the adress for change ?
 * @param  {boolean} [hardened=false] is the adress "hardened" (cannot be calculated from extented private key)
 * @returns {string} the bitcoin address. ex : "bc1qn085dr40dcrhejgve4sky.." 
 * @throws  {Error}  if the wallet is non initialised, or invalid
 */
getPublicAddress( index, change, hardened ) {
    if (!this.HdWallet) 
        throw _BuildError( LibErrors.Wallet_not_initialized )
    // calculates derivation path
    var derivationPath = this.mainDerivationPath 
    // change or main receveiving ?
    if (change)
        derivationPath+= '/1'
    else
        derivationPath+= '/0'
    // index :
    if (!index) 
        index = 0
    derivationPath += "/" + index
    // if we want hardened adresses
    if (hardened)
        derivationPath += "'" // add ' a the add of the path

    // calculates account
    switch (this.walletType) {
        case WalletType.SEGWIT_NATIVE : return this.getSegwitNativePublicAdressFromPath(derivationPath)
        case WalletType.SEGWIT        : return this.getSegwitPublicAdressFromPath(      derivationPath)
        case WalletType.LEGACY        : return this.getLegacyPublicAdressFromPath(      derivationPath)              
        default:            
            throw _BuildError( LibErrors.Invalid_wallet_type, {walletType:walletType})
    }
}
/**
 *  get the private key for an address in WIF format. ex : "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d" 
 * 
 * @public
 * @param  {number}  [index=0]      index of the child key. 0 is the first accout
 * @param  {boolean} [change=false] is the adress for change ?
 * @param  {boolean} [hardened=false] is the adress "hardened" (cannot be calculated from extented private key)
 * @returns {string} private key in base 58. ex : "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d.." 
 * @throws  {Error}  if the wallet is non initialised, or invalid
 */
getPrivateKeyWIF( index, change, hardened ) {
    if (!this.HdWallet) 
        throw _BuildError( LibErrors.Wallet_not_initialized )
    // calculates derivation path
    var derivationPath = this.mainDerivationPath 
    // change or main receveiving ?
    if (change)
        derivationPath+= '/1'
    else
        derivationPath+= '/0'
    // index :
    if (!index) 
        index = 0
    derivationPath += "/" + index
    // if we want hardened adresses
    if (hardened)
        derivationPath += "'" // add ' a the add of the path

    // get the extended private key
    var extPrivateKey = this.HdWallet.getExtendedPrivateKeyFromPath(derivationPath);
    console.assert(extPrivateKey.isPrivateKey())
    // get private key in base 58  format
    return  extPrivateKey.privateKey.toStringBase58()
}

/**
 * get the extended public key fo the account. ex : "zpub6sAxdNfDsummUgnQ7y.." 
 * 
 * @returns {string} the bitcoin extended public key in base 58 format. 
 * @throws  {Error}  if the wallet is non initialised, or invalid
 */
getExtendedPublicKey() {
    // get extended private and public key                                   
    var extPrivKey   = this.HdWallet.getExtendedPublicKeyFromPath( this.mainDerivationPath )
    return extPrivKey.toStringBase58()
}
/**
 * get the extended private key fo the account. ex : "zprvAd4VotcSeiGM.." 
 * 
 * @returns {string} the bitcoin extended public key in base 58 format. 
 * @throws  {Error}  if the wallet is non initialised, or invalid
 */
getExtendedPrivateKey() {
    // get extended private and public key                                   
    var extPrivKey   = this.HdWallet.getExtendedPrivateKeyFromPath( this.mainDerivationPath )
    return extPrivKey.toStringBase58()
}
/**
 *  get a sewigt native adress 
 *  
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/84'/0'/0'/0/0"
 * @returns {string}  bech 32 address. ex : "bc1qn085dr40dcrhejgve4sky.."      
 * @throws  {Error} if <derivationPath> is invalid
 * @see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
 */
getSegwitNativePublicAdressFromPath( derivationPath ) {
    // get the extendede public key
    var extPublicKey = this.HdWallet.getExtendedPublicKeyFromPath(derivationPath);
    console.assert( extPublicKey.publicKey )
    // serialised public key to raw buffer
    var publicKeySerialized = extPublicKey.publicKey.toBuffer();
    // @see https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh
    //      https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    //      https://bitcointalk.org/index.php?topic=4992632.0
    var hashKey       = ripemd160( sha256( publicKeySerialized ) )
    var btcAdress     = bech32Encode( "bc", 0, hashKey );
    return btcAdress
}    
/**
 *  get a sewigt public adress for a derivation path + index. 
 *  
 * @public
 * @param  {string}  derivationPath the derivation path. ex: "m/49'/0'/0'/0/0"
 * @returns {string} address. ex : "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX"      
 * @throws  {Error} if <derivationPath> is invalid
 */
getSegwitPublicAdressFromPath( derivationPath ) {
    // get the extended public key
    var extPublicKey = this.HdWallet.getExtendedPublicKeyFromPath(derivationPath );
    console.assert( extPublicKey.publicKey )
    // serialised public key to raw buffer
    var publicKeySerialized = extPublicKey.publicKey.toBuffer();
    // bitcoin P2WPKH format :
    // If the version byte is 0, and the witness program is 20 bytes:
    // It is interpreted as a pay-to-witness-script-hash (P2WSH) program. 
    // NB : OP_HASH160 is ripemd160( sha256( x ) )
    var hashKey      = ripemd160( sha256( publicKeySerialized ) )
    var scriptSig    = '\x00\x14' + hashKey // \x00 : version byte, \x14=20   witness program
    var addressBytes = ripemd160( sha256( scriptSig)  )       
    var btcAdress    = base58CheckEncode( addressBytes,  PREFIX_P2SH );
    return btcAdress
}
/**
 *  get a legacy public adress for a derivation path + index. 
 *  
 * @public
 * @param   {string}  derivationPath the derivation path. ex: "m/44'/0'/0'/0/0"
 * @returns {stringy} P2PKH address = legacy format. ex : "1E3B4m6BSw7v2A7TiA2YxDTXBZjFEpBmPN"    
 * @throws  {Error}  if <derivationPath> is invalid  
 */
getLegacyPublicAdressFromPath( derivationPath, index ) {
    // get the extended public key
    var extPublicKey = this.HdWallet.getExtendedPublicKeyFromPath(derivationPath );
    console.assert( extPublicKey.publicKey )
    // serialised public key to raw buffer
    var publicKeySerialized = extPublicKey.publicKey.toBuffer();
    // legacy bitcoin format :
    var hash      = ripemd160( sha256( publicKeySerialized ) ) 
    var btcAdress = base58CheckEncode( hash,  PREFIX_P2PKH );
    return btcAdress
}

// generate a cryto secure random buffer of <nbBit> size
getRandomBuffer( nbBit ) {
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
/**
/* get the main derivation path from type
 * @private
 * @returns {string} the mains derivation path.
 * @throws  {struct} if the wallet type is invalid
*/
 _derivationPathFromType( walletType ) {
    switch (walletType) {
        case WalletType.LEGACY:        return DerivationPath.LEGACY_BIP44
        case WalletType.SEGWIT:        return DerivationPath.SEWITG_BIP49    
        case WalletType.SEGWIT_NATIVE: return DerivationPath.SW_NATIVE_BIP84      
        default:
            throw _BuildError( LibErrors.Invalid_wallet_type, {walletType:walletType})
    }
}

}// class BitcoinWallet


