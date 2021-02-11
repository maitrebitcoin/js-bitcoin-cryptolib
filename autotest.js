/**
 ****************************************************** 
 * @file    autotest.js
 * @file    auto tests for the js-bitcoin-cryptolib
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * 
 * @license LGPL-3.0 
 ******************************************************
 */



function FAILED(fonError, valueTested, result, expected, message ) {
     // error
     fonError( valueTested, result, expected, message )
     // stop the test
     throw -1;
}

// fonError : callback called if the test fails
function autotest_sha256( fonError ) {
    // s       : value to hash 
    // expeded : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    function _test_( s, expected  ) 
    {
        // calculate hash
        var hash  = sha256( s )
        // is it the expected result ?
        var hashAsHexString =  hex(hash);
        if (hashAsHexString != expected) {
            // error
            FAILED( fonError, s, hashAsHexString, expected )
        }

    }

    // test some values 
    _test_( "",  
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    _test_( "abc", 
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" )
    _test_( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" )
    _test_( "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" )
     _test_( "the times is 10pm", 
            "ca0c2c84bbbdd964fd76b106be83620eaeaabee5958d597ccecab41afd249605" )          
    _test_( "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 
            "9537c5fdf120482f7d58d25e9ed583f52c02b4e304ea814db1633ad565aed7e9" )          

    _test_( "a".repeat(1000000),  // 1 million a
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" )

    // SUCESS
  
}

// fonError : callback called if the test fails
function autotest_sha512( fonError ) {
    // s       : value to hash 
    // expeded : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    function _test_( s, expected  ) 
    {
        // calculate hash
        var hash  = sha512( s )
        // is it the expected result ?
        var hashAsHexString =  hex(hash);
        if (hashAsHexString != expected) {
            // error
            FAILED( fonError, s, hashAsHexString, expected )
        }

    }

    // test some values 
    _test_( "",  
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    _test_( "abc",  
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    _test_( "The quick brown fox jumps over the lazy dog",  
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6")
    _test_( "be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09",  
            "89728620891234831636ec22de526c96d1587bd89cb18c6efa820de3ee1c78e7bae59dd0eda0e5b452fbf2d45c7a4b2420e1c2532fa0753076c5b74dfca2c046")




    // SUCESS
  
}

// fonError : callback called if the test fails
function autotest_hmac_sha512(fonError) {
       // s       : value to hash 
    // expeded : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    function _test_( k, s, expected  ) 
    {
        // calculate hash
        var hash  = hmac_sha512(k, s )
        // is it the expected result ?
        var hashAsHexString =  hex(hash);
        if (hashAsHexString != expected) {
            // error
            FAILED( fonError, s, hashAsHexString, expected )
        }

    }

    // test values from
    // https://tools.ietf.org/html/rfc4231
    _test_("\x0b".repeat(20), "Hi There",
           "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"  )
    _test_("Jefe", "what do ya want for nothing?",
           "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"  )
    _test_("\xaa".repeat(20), "\xdd".repeat(50),
           "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"  )
   _test_("\xaa".repeat(131), "Test Using Larger Than Block-Size Key - Hash Key First",
           "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"  )


}

// fonError : callback called if the test fails
function autotest_ecdsa( fonError ) {
    var ecdsa = new ECDSA();

    // test public key derivation
    var valTest = "0c34cf6a7d24367baa81ef8331c8cb7ffafc0978ff6cf9e5d873de96142bdb86"
    var priv = ecdsa.privateKeyFromHexString(valTest)
    var pub  = ecdsa.publicKeyFormPrivateKey(priv); 
    var result   = pub.toString()
    var expected ="3068765c2ab75bcfcbd5ae3ccefbdd25b94f414ab0a58c67a780fd437e35c81e,5fa059f6ecab2e2e11a880130b04697859d75eea77f603c715946ed430ef69a4"
    if (result!=expected) {
        FAILED( fonError, valTest, result,expected)
    }

    // sign  a message
    var sMessage = "abdefghijlk12345"                
    var signature = ecdsa.signMessage( sMessage, priv )

    // check signature
    var res = ecdsa.verifySignature(sMessage, signature, pub )
    if (!res.ok) {
        FAILED( fonErrorn, valTest, result,expected, res.message)
    }
    // alter message, should fail
    var res = ecdsa.verifySignature(sMessage+".", signature, pub )
    if (res.ok) {
        FAILED( fonError, valTest, result,expected, "signature should fail")
    }

   // SUCESS
}

