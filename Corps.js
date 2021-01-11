// operations mobulo N

// constructor
function Corps( N ) {
    console.assert( typeof  N == 'bigint' )
    this.N      = N
    // optim for inversion
    this.NMinus1 = this.sub(  N, BigInt(1) )
}

// Addition modulo N
Corps.prototype.add = function ( x,y )  {
     return ( x + y ) % this.N;
}
// Substraction modulo N
Corps.prototype.sub = function ( x,y )  {
     return ( x - y ) % this.N;
}

// Multiplication modulo N
Corps.prototype.mult = function ( x,y )  {
    return ( x * y ) % this.N;
}

// exponentiation  : x ^ y
Corps.prototype.exp = function ( x,y )  {
     var r = BigInt(1)
     while (y>0) {
        r = mult( r, r)
        // if bit 0 is set
        if (y % 1 == 1) {
            r = mult( r, x)
        }
        y = y / 2
     }
     return r;
}

// Inversion : 1/x.
// return y such a x*y = 1
Corps.prototype.inversion = function ( x )  {
    console.assert( x != 0 );
    // euler formula
    return exp( x, this.NMinus1 )
}
