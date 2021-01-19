// auto tests for the js-bitcoin-cryptolib

function autotest_sha256( fonError ) {
    // x       : "" 
    // expeded : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    function _test_( s, expected  ) 
    {
        // calculate hash
        var hash  = sha256( s )
        // is it the expected result ?
        var hashAsHexString =  hex(hash);
        if (hashAsHexString != expected) {
            // error
            fonError( s, hashAsHexString, expected )
            // stop the test
            throw -1;
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