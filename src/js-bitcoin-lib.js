/**
 ****************************************************** 
 * @file    js-bitcoin-lib.js
 * @file    main file for js-bitcoin-cryptolib
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see     https://en.wikipedia.org/wiki/SHA-2
 * @license LGPL-3.0 
 * 
 * @example <script src='js-bitcoin-lib.js'></script>
 * 
 ******************************************************
 */

 // get url for "js-bitcoin-lib.js.js"
 // ex = "file:///C:/Source/github/js-bitcoin-cryptolib/js-bitcoin-lib.js"
var scripts    = document.getElementsByTagName("script") 
var lastScript = scripts[scripts.length-1]
var myUrl      = lastScript.src;
// extract path
var lastSlash  = myUrl.lastIndexOf('/')
var libPath    = myUrl.substr( 0, lastSlash ) + '/'

function include_js( jsfile ) {
    document.write("<script src='" + libPath + jsfile +"'><"+"/script>");
}

// include all needeed js files in the lib
include_js('gfield.js');
include_js('ellipticurve.js');
include_js('ecdsa.js');
include_js('hash.js');
include_js('encodedecode.js');
include_js('hdwallet.js');
include_js('bip39.js');
