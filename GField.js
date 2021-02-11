/**
 ****************************************************** 
 * @file    gfield.js 
 * @file    Galois Field on N/nN : math operations mobulo N
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

class GFied { 

// constructor
constructor( N ) {
    console.assert( typeof  N == 'bigint' )
    this.N      = N
    // optim for inversion
    this.NMinus2 = this.sub(  N, BigInt(2) )
}
// moludo N
modulo(x){
    return  x % this.N;
}

// Addition modulo N
add( x,y )  {
     return ( x + y ) % this.N;
}
// Substraction modulo N
sub( x,y )  {
     var res = ( x - y ) % this.N;
     // the result must be positive
     if (res<0) 
         res += this.N;
    return res
}
// Negation modolo N. -X
negate(x) {
    if (x==0) return 0
    var res = ( this.N - x ) % this.N
    console.assert(  res+x == this.N )
    return res
}

// Multiplication modulo N
mult ( x,y )  {
    return ( x * y ) % this.N;
}
// square modulo N : x^2
square( x )  {
    return ( x * x ) % this.N;
}
// cube modulo N : x^3
cube ( x )  {
    return ( x * x * x ) % this.N;
}

// exponentiation  : x ^ y
exp( x,y )  {
     // opération result
     var r = BigInt(1)
     // X^2N, 
     var xPow2N = x
     while (y>0) {
      
        // if bit 0 is set
        var bit1 = y % BigInt(2)
        if (bit1 == BigInt(1)) {
            r = this.mult( r, xPow2N)
        }
        y = y / BigInt(2)
        xPow2N = this.mult( xPow2N, xPow2N)
     }
     return r;
}

// Inversion : 1/x.
// return y such a x*y = 1
inversion ( x )  {
    console.assert( x != 0 );
    // euler formula : 1/x = x ^ (n-2)
    var invx = this.exp( x, this.NMinus2 );
    console.assert( this.mult(x, invx) == BigInt(1) )
    return invx  ;
}


}//class GFied