// operations mobulo N

// constructor
function Corps( N ) {
    console.assert( typeof  N == 'bigint' )
    this.N = N
}
// Addition modulo N
Corps.prototype.add = function ( a,b )  {
     r = (a + b ) % this.N;
     return r;
}

// Multiplication modulo N
Corps.prototype.mult = function ( a,b )  {
     r = (a * b ) % this.N;
     return r;
}