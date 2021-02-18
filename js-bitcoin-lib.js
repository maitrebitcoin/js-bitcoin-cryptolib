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

function include_js(s) {
    document.write("<script src='" +s +"'><"+"/script>");
}

// include all needeed js files in the lib
include_js('gfield.js');
include_js('ellipticurve.js');
include_js('ecdsa.js');
include_js('sha.js');
include_js('encodedecode.js');
include_js('hdwallet.js');

