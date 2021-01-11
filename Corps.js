// operations mobulo N

// constructor
function Corps( N ) {
    console.assert( typeof  N == 'bigint' )
    this.N      = N
    // optim for inversion
    this.NMinus2 = this.sub(  N, BigInt(2) )
}

// Addition modulo N
Corps.prototype.add = function ( x,y )  {
     return ( x + y ) % this.N;
}
// Substraction modulo N
Corps.prototype.sub = function ( x,y )  {
     var res = ( x - y ) % this.N;
     // the result must be positive
     if (res<0) 
         res += this.N;
    return res
}

// Multiplication modulo N
Corps.prototype.mult = function ( x,y )  {
    return ( x * y ) % this.N;
}
// square modulo N : x^2
Corps.prototype.square = function ( x )  {
    return ( x * x ) % this.N;
}
// cube modulo N : x^3
Corps.prototype.cube = function ( x )  {
    return ( x * x * x ) % this.N;
}

// exponentiation  : x ^ y
Corps.prototype.exp = function ( x,y )  {
     var r = BigInt(1)
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
Corps.prototype.inversion = function ( x )  {
    console.assert( x != 0 );
    // euler formula
    var invx = this.exp( x, this.NMinus2 );
    console.assert( this.mult(x, invx) == BigInt(1) )
    return invx  ;
}
