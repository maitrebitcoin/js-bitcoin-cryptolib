// auto tests for the js-bitcoin-cryptolib
// test for sha2-256 dans ecdsa se

function FAILED(valueTested, result, expected, message ) {
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
            FAILED( s, hashAsHexString, expected )
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
function autotest_ecdsa( fonError ) {
    var ecdsa = new ECDSA();

    // test public key derivation
    var valTest = "0c34cf6a7d24367baa81ef8331c8cb7ffafc0978ff6cf9e5d873de96142bdb86"
    var priv = ecdsa.privateKeyFromHexString(valTest)
    var pub  = ecdsa.publicKeyFormPrivateKey(priv); 
    var result   = pub.toString()
    var expected ="3068765c2ab75bcfcbd5ae3ccefbdd25b94f414ab0a58c67a780fd437e35c81e,5fa059f6ecab2e2e11a880130b04697859d75eea77f603c715946ed430ef69a4"
    if (result!=expected) {
        FAILED( valTest, result,expected)
    }

    // sign  a message
    var sMessage = "abdefghijlk12345"                
    var signature = ecdsa.signMessage( sMessage, priv )

    // check signature
    var res = ecdsa.verifySignature(sMessage, signature, pub )
    if (!res.ok) {
        FAILED( valTest, result,expected, res.message)
    }
    // alter message, should fail
    var res = ecdsa.verifySignature(sMessage+".", signature, pub )
    if (res.ok) {
        FAILED( valTest, result,expected, "signature should fail")
    }

   // SUCESS
}