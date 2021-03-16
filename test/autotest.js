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

/**
 * run all tests
 *  @param {fonError}  function called if a test fails
 *  @param {fonStepOK} function called if a test completed successfully
 *  @param {fonEnd}    function called a the end of all tests if no error
 * 
*/
function autotest_all(fonError, fonStepOK, fonEnd ){
    var tabTestName  = new Array( 'encodeDecode', 'bech32', 
                                  "ripemd160", "sha512", "sha256", "hmac_sha512", 
                                  "bip39", "pbkdf2_hmac512", "ecdsa","bip32","bip49","bip84" )
    
    var numTest = 0;

    /**
     * run  test
     * @param {int} numTest 
     * @async
     */     
    function _runOneTestAync(numTest) {
         var testName = tabTestName[numTest];
        // Run tests...
        // ex :  autotest_sha512(fonError)
        try {
            eval("autotest_"+ testName + "(fonError)")
        }
        catch (error)  {
            if ( error == -2)
                throw -2
            FAILED( fonError, "", "", testName + ' ERROR - \n' +error)     
        }

        // test <testName> is OK
        fonStepOK(testName)
        // last testt ?
        if (numTest+1>=tabTestName.length)
        {
            fonEnd()
            return;
        }
        // Run next test async
        setTimeout( () => {_runOneTestAync(numTest+1)}, 0)           
    };
   
    // Start with 1st test :
   _runOneTestAync(0)

}


function FAILED(fonError, valueTested, result, expected, message ) {
     // error
     try {
        fonError( valueTested, result, expected, message )
     }
     catch (error)  {
        // stop the test
        throw -2;
    }     
     // stop the test
     throw -1;
}

// fonError : callback called if the test fails
function autotest_bech32( fonError ) {
    // s       :  value to encode. buffer as hex
    // expeded : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    function _test( s, expected  ) 
    {
        // calculate hash
        var buffer = bufferFromHex(s)
        var res    = bech32Encode( "bc", 0, buffer  )
        // is it the expected result ?
        if (res != expected) {
            // error
            FAILED( fonError, s, res, expected, "" )
        }
        // check decodinf
        try {
            var decoded = bech32Decode( res )
            if (decoded.prefix != "bc")   
                FAILED( fonError, s, decoded.prefix , "bc", "" )
            if (decoded.version != 0)   
                FAILED( fonError, s, decoded.version , "0", "" )                
            if (hex(decoded.buffer) != s)   
                FAILED( fonError, s, hex(decoded.buffer), expected, "" )
        }
        catch( err )  {
            if (err==-2) throw -2;
            FAILED( fonError, s, res, expected, err )
        }_test
    }//

    // test some values 
    _test( "0e140f070d1a001912060b0d081504140311021d030c1d03040f1814060e1e16",  
           "bc1qpc2q7pcdrgqpjysxpvxss9gyzsp3zqsaqvxp6qcypuvpgpswrctqtvxys3")
    _test( "0000000000000000000000000000000000000000000000000000000000000000",  
           "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqthqst8")
    _test( "8888888888888888888888888888888888888888888888888888888888888888",  
           "bc1q3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyquddz7w")
    _test( "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  
           "bc1qlllllllllllllllllllllllllllllllllllllllllllllllllllsffrpzs")        
    _test( "bc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1fbc1f",  
           "bc1qhs0mc8aur77pl0qlhs0mc8aur77pl0qlhs0mc8aur77pl0qlhs0se2mha8")   
    _test( "ddddddddddddddddddddddddddd7777777777777777777777777777777777777",  
           "bc1qmhwamhwamhwamhwamhwam4mhwamhwamhwamhwamhwamhwamhwamsa66n94")
           
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
/**
 * test the ripemd160() fucntion
 * @param {function} fonError callback called if the test fails
 */
function autotest_ripemd160( fonError ) {
    // s       : value to hash 
    // expeded : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    function _test_( s, expected  ) 
    {
        // calculate hash
        var hash  = ripemd160( s )
        // is it the expected result ?
        var hashAsHexString =  hex(hash);
        if (hashAsHexString != expected) {
            // error
            FAILED( fonError, s, hashAsHexString, expected )
        }

    }

    // test some values 
    _test_( "",  
            "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    _test_( "abc",  
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    _test_( "The quick brown fox jumps over the lazy dog",  
            "37f332f68db77bd9d7edd4969571ad671cf9dd3b")
    _test_( "be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09",  
            "dbeed69c6320579a69e6d25f443dccc8dc22532f")
    _test_( "be688838ca8686e5c90689bf2ab585cef1137c999b48c70b92f67a5c34dc15697b5d11c982ed6d71be1e1e7f7b4e0733884aa97c3f7a339a8ed03577cf74be09_",
            "ec7a52a5cd601f79c1e5e7fd6dba0b9806eea53f")

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

function autotest_pbkdf2_hmac512(fonError) {
     
    
    function _test_nbIter( nbIteration, expected  ) 
    {
        // calculate hash
        var hash  = PBKDF2_512( hmac_sha512, "password","salt", nbIteration )
        // is it the expected result ?
        var hashAsHexString =  hex(hash);
        if (hashAsHexString != expected) {
            // error
            FAILED( fonError, nbIteration, hashAsHexString, expected )
        }

    }
    function _test_bip39( phrase, expected  ) 
    {
        // calculate hash
        var hash  = seedFromPhrase( phrase )
        // is it the expected result ?
        var hashAsHexString =  hex(hash);
        if (hashAsHexString != expected) {
            // error
            FAILED( fonError, nbIteration, hashAsHexString, expected )
        }

    }    

    // test vectors from
    // https://stuff.birkenstab.de/pbkdf2/
    _test_nbIter(1,  "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce" )
    _test_nbIter(2,  "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e" )
    _test_nbIter(3,  "b6b07cb2cebf4ad84468391a543824fccffe0e0769dbe6bddf10a65673c4b648e612d44918f9ce9a19a1294cf5140628084ba994c3b21a4ef4741220b811c633" )
    _test_nbIter(4,  "a3e4e33fc661f01e0a0824950576713fca8c6c27971aff4c3088b3d41442e723d4b603f204e07129f54e7f9a26456eab8ed8406b7a7a0c7917a7635abde2b1b7" )
    _test_nbIter(8,  "5716406b47a8cf8738df359a1bfec0c6b503db9232ccb60971f3d21b511a8297776c8451663207d3f5f057268c880be73ccfe22a0710957f9d40c28fbe412412" )
    _test_nbIter(16, "8834dcafecf53126ccfe4d46c676164def1433d7422109d59e19ab27b51c40402309aaad1b92656a55ce1667f381b375c44e88f6192d6082294d0336580a4111" )
    _test_nbIter(128,"76436aade02c0cd4ab5df2b03eeff4c9fb060462e293226242bafcc75229b8cef403f4db8b0c8186062e28e25036af89f27dcaf9309b89895941de8746bc64bf" )

    // test bip39
    // test vectors from
    // https://iancoleman.io/bip39/
    _test_bip39( "pistol thunder want public animal educate laundry all churn federal slab behind media front glow", 
                 "6e85439607050fad311b71238aacdd27d3095329201baa367c43e93869621de213f2c75dac958ecc1a87d55a94baf02e223de1d686c276882c112e841b01a8df" )

}

function autotest_bip39(fonError) {
       
    function _test( bufferHasHex, expected  ) 
    {
        var buffer = bufferFromHex(bufferHasHex)
        // calculate hash
        var phrase  = bip39phraseFromRandomBuffer( buffer  )
        // is it the expected result ?
        if (phrase != expected) {
            // error
            FAILED( fonError, bufferHasHex, phrase, expected )
        }

    }
    // test vectors 
    // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    _test("00000000000000000000000000000000",
           "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    _test("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
          "legal winner thank year wave sausage worth useful legal winner thank yellow")
    _test("80808080808080808080808080808080",
          "letter advice cage absurd amount doctor acoustic avoid letter advice cage above")         
    _test("ffffffffffffffffffffffffffffffff",
          "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")         
    _test("9e885d952ad362caeb4efe34a8e91bd2",
          "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic")               
    _test("000000000000000000000000000000000000000000000000",
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent")
    _test("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
          "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will")
    // 512 bitq
    _test("0000000000000000000000000000000000000000000000000000000000000000",
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
    _test("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
          "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
    _test("8080808080808080808080808080808080808080808080808080808080808080",
          "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless")
    _test("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote")
    _test("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
          "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length")
    _test("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
          "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",)
 

}


// fonError : callback called if the test fails
function autotest_ecdsa( fonError ) {
    var ecdsa = new ECDSA();

    // test public key derivation
    var valTest = "0c34cf6a7d24367baa81ef8331c8cb7ffafc0978ff6cf9e5d873de96142bdb86"
    var priv = ecdsa.privateKeyFromBigInt(BigInt( "0x" + valTest))
    var pub  = ecdsa.publicKeyFromPrivateKey(priv); 
    var result   = hex( pub.toBuffer() )
    //var expected ="3068765c2ab75bcfcbd5ae3ccefbdd25b94f414ab0a58c67a780fd437e35c81e,5fa059f6ecab2e2e11a880130b04697859d75eea77f603c715946ed430ef69a4"
    var expected ="023068765c2ab75bcfcbd5ae3ccefbdd25b94f414ab0a58c67a780fd437e35c81e"
    if (result!=expected) {
        FAILED( fonError, valTest, result,expected)
    }

    // sign  a message
    var sMessage = "abdefghijlk12345"                
    var signature = ecdsa.signMessage( sMessage, priv )

    // check signature
    var res = ecdsa.verifySignature(sMessage, signature, pub )
    if (!res.ok) {
        FAILED( fonError, valTest, result,expected, res.message)
    }
    // alter message, should fail
    var res = ecdsa.verifySignature(sMessage+".", signature, pub )
    if (res.ok) {
        FAILED( fonError, valTest, result,expected, "signature should fail")
    }

    // test rfc6979 
    // https://bitcointalk.org/index.php?topic=285142.40
    test_vectors = [
        ["1", "Satoshi Nakamoto", "8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15", "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"],
        ["1", "All those moments will be lost in time, like tears in rain. Time to die...", "38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3", "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"],
        ["FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", "Satoshi Nakamoto", "33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90", "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d06b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"],
        ["f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181", "Alan Turing", "525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1", "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"],
        ["e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2", "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!", "1F4B84C23A86A221D233F2521BE018D9318639D5B8BBD6374A8A59232D16AD3D", "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6"]
    ];   
    for (const testVectorI of test_vectors)  { 
        var privateKeyI256  = BigInt("0x" + testVectorI[0] )
        var message         = testVectorI[1] // ex :  "Satoshi Nakamoto"
        var expectedK       = BigInt("0x" + testVectorI[2]  )
        var signatureBuffer = testVectorI[3] 
        var privateKey = ecdsa.privateKeyFromBigInt( privateKeyI256 );
        // test K
        var k = ecdsa._rfc6979(privateKey, message)
        if ( k != expectedK)
            FAILED( fonError, valTest, hex(k),hex(expectedK), "k")
 
        var signature  = ecdsa.signMessage( message, privateKey, "rfc6979" )
        var expectedR  = BigInt("0x" + signatureBuffer.substr(0,64)) // ex : "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
        var expectedS  = BigInt("0x" + signatureBuffer.substr(64)  ) // ex : "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
        if (signature.r != expectedR )  {
            FAILED( fonError, valTest, signature.r,expectedR, "!=")
        }
   
        if (signature.s != expectedS )  {
            FAILED( fonError, privateKeyI256, hex(signature.s), hex(expectedS), "!=")
        }    
    }

   // SUCESS
}

// fonError : callback called if the test fails
function autotest_bip32( fonError ) {
    /** 
     * test the  .getMasterKey() method
     * @param {string}   seedHex  seed buffer in hex forma. ex : "("6e85439607050fad311b71238..."
     * @param {expected} expected expected result in base 58. ex  "xprv9s21ZrQH143K4b..."
     * seed            :  seed buffer in hexa.
     */
    function _test_seed( seedHex, expected  ) 
    {
        // calculate rood
        var seed  = bufferFromHex(seedHex)
        var bip32 = new HdWallet( seed, WalletType.LEGACY );
        var res   = bip32.getMasterKey();
        var res58 = res.toStringBase58()

        // is it the expected result ?
        if (res58 != expected) {
            // error
            FAILED( fonError, seedHex, res58, expected )
        }
    }
    /** 
     * test the  .getPrivateKeyFromPath() method
     * @param {string}   seedHex  seed buffer in hex forma. ex : "("6e85439607050fad311b71238..."
     * @param {expected} expected expected result in base 58. ex  "xprv9s21ZrQH143K4b..."
     * seed            :  seed buffer in hexa.
     */    
    function _test_derivation( seedHex, deivationPath, expected, expectedPub  ) 
    {
        // calculate rood
        var seed  = bufferFromHex(seedHex)
        var bip32 = new HdWallet( seed, WalletType.LEGACY );
        var res;
        try {
           res   = bip32.getExtendedPrivateKeyFromPath(deivationPath)
        } catch( err ) {
            FAILED( fonError, seedHex, res58, expected, deivationPath + '\n' +res.error )
        }
        var res58 = res.toStringBase58()
        // is it the expected result ?
        if (res58 != expected) {

            // error
            FAILED( fonError, seedHex, res58, expected, deivationPath )
        }
        if (!expectedPub) return; // OK
        try { res   = bip32.getExtendedPubliceKeyFromPath(deivationPath) }
        catch( err ) {
             FAILED( fonError, seedHex, res58, expected, deivationPath + '\n' +err.error )
        }
        var res58pub = res.toStringBase58()
        // is it the expected result ?
        if (res58pub != expectedPub ) {

            // error
            FAILED( fonError, seedHex, res58pub, expectedPub, deivationPath )
        }      
        // OK
    }    

    // check tha the value raise an error
    function _test_error( string58  ) 
    {
        var errFound;
        try {
            var res=  HdWallet.getExtendedKeyFromStringBase58(string58)
        } catch (err) {
            errFound = err;
        }
       if (!errFound) {
            FAILED( fonError, string58, res, "ERROR expected" )
       }

    }
    var phrase ="pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
    var seed = "6e85439607050fad311b71238aacdd27d3095329201baa367c43e93869621de213f2c75dac958ecc1a87d55a94baf02e223de1d686c276882c112e841b01a8df";       

    _test_seed(seed, "xprv9s21ZrQH143K4b44oYF6VxMLbBroCaDgiWetWXeDHanBdreeF8bQpUndSvVgHHwQNkifjfwZXgY8Fxub73dLbnJ7we9FSaae5PvXjBTfw4Y");

    // invalid values, should raise an error           
    _test_error("")
    _test_error("*bad string")
    _test_error("xprv9s21ZrQH143K4b44oYF6VxMLb")
    _test_error("xprv9s21ZrQH143K4b44oYF6VxMLbBroCaDgiWetWXeDHanBdreeF8bQpUndSvVgHHwQNkifjfwZXgY8Fxub73dLbnJ7we9FSaae5PvXjBTfw4Z")  // CRC
   
    // test derivation paths
    _test_derivation( seed, "m/0",    "xprv9uVXYtuVbPpJQFs3ccU7odsG3m6iPp5jsAqXY1NstBEeLB1sj3sh572x8iSo16if7b9DFRXXZdMvHKvSm39oKNR7uXCHKwM9gc8EZgZk3bA" )
    _test_derivation( seed, "m/1",    "xprv9uVXYtuVbPpJSMWKfrQRqWHjqisVFJtWSxgTL1Eejq115SRggWmPVJDvSKWMMWoQvQdXHifwXhpFhzjaydbPghB9VHVagms7PNCruPnU8Co" )
    _test_derivation( seed, "m/0'",   "xprv9uVXYtudw4MGZTnWJ1aCcC9jLk7wFMWuLGyYwTiLVkFRWcyMCVQt6YShPR25j4LeTDuE7PdEhiQUAqCpT227JyhnGu5z9Sf4F9srXjLHwnx" )
    _test_derivation( seed, "m/0'/0'","xprv9xc6Adnpycv3xyzDLojgHuRXKYQExX9qYhQgQJGnRJRt6UzPvszTsRriHtuagmjmjQQLbgCjLij6ZRWLgc3vGCKqcW6SbsABYLdhHqP6zq8" )
    _test_derivation( seed, "m/0'/1", "xprv9xc6AdngdxP5rCTgvBexpJWZyEFemND99w7g9VnEU3wJ9CD6bo2Kv7JKE8HNudLW8gwx8PuVt1xDnVPMN37JqG7AiXYiQVHbhVxYHas19w9" )
    // BIP44
    _test_derivation( seed, "m/44'/0'/0'/0", "xprv9zqEnwRp3fCUBPZWaxV2ZnbLYfQxhVm4VfF7bh9tfSmF5eBTUxZLMnUHGTwy4ygakVWz9Y4w3LirEbrCSwTJoiFJ1JK92cqaNxKJPY6xkHc",
                                             "xpub6DpbCSxht2kmPsdygz22vvY56hFT6xUurtAiQ5ZWDnJDxSWc2Vsauanm7mMWozi1gzB4WhZ9NFstB6JW84Naj3XiSj4r7p9NAKLQv7AFcKu" )

    // official test Vectors
    var seed = "000102030405060708090a0b0c0d0e0f";       
    _test_derivation( seed, "m",    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi" )

}

function autotest_bip49( fonError ) {
    /** 
     * test the  .getMasterKey() method
     * @param {string}   seedHex  seed buffer in hex forma. ex : "("6e85439607050fad311b71238..."
     * @param {expected} expected expected result in base 58. ex  "xprv9s21ZrQH143K4b..."
     * seed            :  seed buffer in hexa.
     */
    function _test( seedHex, expectedExtPrivate, expectedExtPub, expectedAdress0  ) 
    {
        // calculate rood
        var seed  = bufferFromHex(seedHex)
        // create a new bip32 wallet
        var bitcoinWallet   = new BitcoinWallet( WalletType.SEGWIT );
        bitcoinWallet.initFromSeed(seed)
        var bip32Wallet = bitcoinWallet.HdWallet;
        // bip 49 derivation path
        var derivationPath = "m/49'/0'/0'/0"

        // check extended keys
        var extPrivate   = bip32Wallet.getExtendedPrivateKeyFromPath(derivationPath)
        var extPrivateStr = extPrivate.toStringBase58();
        if (extPrivateStr != expectedExtPrivate) {
            // error
            FAILED( fonError, seedHex, extPrivateStr, expectedExtPrivate )
        }
        var extPublic  = bip32Wallet.getExtendedPubliceKeyFromPath(derivationPath)
        var extPublicStr = extPublic.toStringBase58();
        if (extPublicStr != expectedExtPub) {
            // error
            FAILED( fonError, seedHex, extPublicStr, expectedExtPub )
        }        

        // get 1st valid public address 
        var pubAdress   = bitcoinWallet.getSegwitPublicAdressFromPath(derivationPath + "/0")
        // is it the expected result ?
        if (pubAdress != expectedAdress0) {
            // error
            FAILED( fonError, seedHex, pubAdress, expectedAdress0 )
        }
    }
    
    // abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
    _test("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
          "yprvAKoaYbtSYB8DmmBt2Z7TgukWphdCiSMRVdzDK3aHUSna8jo6xnG41jQ11ToPk4SQnE5sau6CYK4od9fyz53mK7huW4JskyMMEmixACuyhhr",
          "ypub6Ynvx7RLNYgWzFGM8aeU43hFNjTh7u5Grrup7Ryu2nKZ1Y8FWKaJZXiUrkJSnMmGVNBoVH1DNDtQ32tR4YFDRSpSUXjjvsiMnCvoPHVWXJP",
          "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf")
    //bonus mean flower scrap plug output eyebrow urge drastic such minimum prefer
    _test("de9177fb34632d998a552b7f41bc9f42d43910da5aa6cedf83997a2d4a362d4a642a56e674e8cc686452ac300c4404210413a2330d39ef5eff2b54eb933f77ed",
          "yprvALiRambGqxJTUwfBKeBNgejTdYH3N7SwJswSQmtusFc5H3g2BVQofZ2hwwKy9GX47UYZQvNEWVrdgtjS6QCKPnyGF1pwjzGLHdVXw69JGKi",
          "ypub6ZhmzH8AgKrkhRjeRfiP3ngCBa7XmaAng6s3DAJXRb949r1Aj2j4DMMBoEVa1KoWWZrkaKdn8y2u6nJyCBBcEHx5AfDAnNFmc8ayUpzLru3",
          "3BRTnZiug1MdARwxbSw9KDPfxjDDW6D1YZ")  
    //pistol thunder want public animal educate laundry all churn federal slab behind media front glow
    _test("6e85439607050fad311b71238aacdd27d3095329201baa367c43e93869621de213f2c75dac958ecc1a87d55a94baf02e223de1d686c276882c112e841b01a8df",
          "yprvAM9dMrT1XETGDBxySS599Xk9Y5B1rEaa55vkE156GcvScpyig96eAnKizNa3wzLYzyEeLhSXtaFgT6vLAky9en93YE5Avn7EpFmqFoV43V3",
          "ypub6a8ymMyuMc1ZRg3SYTc9Wfgt671WFhJRSJrM2PUhpxTRVdJsDgQtiaeCqg8HViSzYpLLe4JCRvruh6Z9Pjee32WpoUUXAbvT2mTg4pTBRCd",
          "33jf9oZuoZuySWYATVKbgLRva26f5X9iPG")  
}

/**
 * test BitcoinlWallet in bip 84 mode.
 * @param {function } fonError called if one of the test fails
 * @see https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
 */
function autotest_bip84( fonError ) {
    /** 
     * test the  .getMasterKey() method
     * @param {string}   seedHex  seed buffer in hex forma. ex : "("6e85439607050fad311b71238..."
     * @param {expected} expected expected result in base 58. ex  "xprv9s21ZrQH143K4b..."
     * seed            :  seed buffer in hexa.
     */
    function _test( mnemonic , expectedExtPrivate0, expectedExtPub0, expectedPrivate0, expectedPublic0, expectedAdress0  ) 
    {
        // calculate rood
        var seed  = seedFromPhrase(mnemonic)
        // create a new bip32 wallet
        var bitcoinWallet  = new BitcoinWallet(  WalletType.SEGWIT_NATIVE );
        bitcoinWallet.initFromSeed(seed)
        var bip32Wallet    = bitcoinWallet.HdWallet
        // bip 49 derivation path
        var derivationPath = DerivationPath.SW_NATIVE_BIP84 

        // check extended keys
        var extPrivate   = bip32Wallet.getExtendedPrivateKeyFromPath(derivationPath)
        var extPrivateStr = extPrivate.toStringBase58();
        if (extPrivateStr != expectedExtPrivate0) {
            // error
            FAILED( fonError, mnemonic, extPrivateStr, expectedExtPrivate0 )
        }
        var extPublic  = bip32Wallet.getExtendedPubliceKeyFromPath(derivationPath)
        var extPublicStr = extPublic.toStringBase58();
        if (extPublicStr != expectedExtPub0) {
            // error
            FAILED( fonError, mnemonic, extPublicStr, expectedExtPub0 )
        }        
        // check private/public ket for adddres 0
        var privKey = bip32Wallet.getPrivateKeyFromPath(derivationPath +"/0" , 0)   
        var privKeyStr = privKey.toStringBase58()
        if (privKeyStr != expectedPrivate0) 
            FAILED( fonError, mnemonic, privKeyStr, expectedPrivate0 )

        var pubKey = bip32Wallet.getPublicKeyFromPath(derivationPath + "/0",0)
        var pubKeyStr = hex( pubKey.toBuffer() )
        if (pubKeyStr != expectedPublic0) 
            FAILED( fonError, mnemonic, pubKeyStr, expectedPublic0 )    
   
        // get 1st valid public address 
        var pubAdress   = bitcoinWallet.getPublicAddress(0,false)
        // is it the expected result ?
        if (pubAdress != expectedAdress0) {
            // error
            FAILED( fonError, mnemonic, pubAdress, expectedAdress0 )
        }
    }
    
    // mnemonic , expectedExtPrivate0, expectedExtPub0, expectedPrivate0, expectedPublic0, expectedAdress0 
    _test("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
          "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
          "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
          "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
          "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
          "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")

    _test("remove movie armor media visit virus emotion wisdom time shine under wheat blossom faculty always",
          "zprvAdDkXqnuuju4iDBHpcojnUexeyL9P7qoGbY72wAjLrfkYTj1uVuTcsitV4WHopjfcX57Lt6ssUQGcBWRBMyedJdAd4zDpowbc8cCLRpp5Ti",
          "zpub6rD6wMKok7TMvhFkveLk9cbhD1AdnaZedpThqKaLuCCjRG4AT3DiAg3NLNPWvS2bFBeWYq1yFwXrE36wggbdC1g6je3AGyk6oYvzZ1YVQoN",
          "L44cV9s8ADP2UYXuKNDk5fqnV57CqY9tDEubFa7daNdZpfyQEjZo",
          "02acbcfd1fb95a847e1394cbe039c4a024b977b38b007aeb102682275c84e35866",
          "bc1qzsmjy0whj9r3fl78nlfypxxhvyt0m2g3e7hxja")

      _test("insane fiction smile add angry lesson guitar bargain simple this slide upper episode insane color now off spread maple glide meat violin once fade",
          "zprvAdqnoecVWYZMVyfy42q4xCyp3P3YbHtCoaSDQe1VjC7CkzgmZGqXPc8LXtK5ZvMWgoBuCFwh6BbNCuwm59gjTx8D933NWJPMysYef67eA1t",
          "zpub6rq9DA9PLv7eiTkSA4N5KLvYbQt2zkc4AoMpD2R7HXeBdo1v6p9mwQSpPC481b2YaBKWHcP8tbQEY93mj4soSosb1nNSKzcoZzu9Zqvujgz",
          "L4GcZcYxTNc5L3TTUUNxZG1AXRtLgG2e7mwMD4DVTUawk71gCU4E",
          "03e8db2d7d93791e7693e3eebe98eb8e63595f49000e74cf359e07a4af2e47e448",
          "bc1qnkeur7kg9qkenhlkwtkmgepx9qwhxywj8se682")

    _test("situate before sell found usage useful caution banner stem autumn decrease melt",
          "zprvAdDppLFvZ2qNbJXHk1mKz6L3LWkAma3UZVmnZ9cBHtQdMznnmRZqHPdaWaoiGKnko45eHrjqrA1VbS6sN1Xqe2iAeS22A2RtBGADQ2sokQ8",
          "zpub6rDBDqnpPQPfonbkr3JLMEGmtYafB2mKvihPMY1nrDwcEo7wJxt5qBx4MteUGCsYHBFUpQisyXuFkiyi5wcau8oKjdMnfgRtYdaSi2zruqg",
          "KxJyAXFHCfj38gvQLsPPUibW6kTzGDUVmXdbFQSdEH1JxpDk86id",
          "0255868ee72b99229153dd1ca1e357a4ef03fa9419f8895cf4e272b2f7d1a837e2",
          "bc1q2rw2yugvcux0dn5jk3a9l85up3z6tcdqjqq3ch")          
}


/**
 * test various encoding/decoding function.
 * @param {function } fonError called if one of the test fails
 */
function autotest_encodeDecode( fonError ) {
    // test 1 func 
    function _test( fnEncode , fnDecode, input, expectedOutputParam, fnConvertOuput  ) 
    {
        // check encode
        var output = fnEncode( input )
        var expectedOutput;
        if (fnConvertOuput)
            expectedOutput = fnConvertOuput(expectedOutputParam)
        else 
            expectedOutput = expectedOutputParam
        // check encoding
        if (output != expectedOutput) {
               // error
               FAILED( fonError, input, fnConvertOuput ?  fnConvertOuput(output):output, expectedOutputParam, "encode" )
        }        
        if (!fnDecode)
            return;
        // check decode
        var inputDecoded = fnDecode( output )
        if (inputDecoded != input) {
            // error
            FAILED( fonError, input, inputDecoded, inputDecoded, "decode" )
        }       
    }

    // hex to/from buffer
    _test( hex, undefined, 0x10203,    "10203" )
    _test( hex, undefined, 0xFF,       "ff"    )  
    _test( hex, undefined, 0x12345678, "12345678"    )  
    _test( hex, undefined, BigInt("0xabcdef0123456789"), "abcdef0123456789")  
    _test( hex, undefined, "\x00\xab\xcd\xef\x01\x23\x45\x67\x89", "00abcdef0123456789")  
    _test( bufferFromHex, hex,  "010203",             "010203", bufferFromHex )
    _test( bufferFromHex, hex,  "abcdef0123456789",   "abcdef0123456789", bufferFromHex )
    _test( bufferFromHex, undefined,  "FFDD",         "\xFF\xDD" )

    // base58
    _test( base58Encode, base58Decode, "",  "" )
    _test( base58Encode, base58Decode, "test",  "3yZe7d" )
    _test( base58Encode, base58Decode, "test Me Please !",  "FNe9LCh9EQnyhK2kbhNqhA" )  
    _test( base58Encode, base58Decode, sha256("test Me Please !"),  "Gje4fyjU9c9Pz3Dr8PvW9e5xQeq4CGUAaxNy3NsxTRx3" )
    _test( base58CheckEncode, base58CheckDecode, "",  "3QJmnh" )
    _test( base58CheckEncode, base58CheckDecode, "test",  "LUC1eAJa5jW" )
    _test( base58CheckEncode, base58CheckDecode, bufferFromHex("05343769f026e918bad7b3c01ca1983f82707c9605"),  "36T7SjoDy8t2PgBfZrtNFSqBXeiTc5uw1X" )
    _test( base58CheckEncode, base58CheckDecode, bufferFromHex("05f78c9ecfc84f9f3d71844f7ccf752f51f1223420"),  "3QFwHQ8cENtVBZWUjzaFE6vgaSTv5p7B6Q" )

    // bech 32 - TODO

}