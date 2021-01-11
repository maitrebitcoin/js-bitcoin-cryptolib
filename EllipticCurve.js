// elliptic curve

// point of an elliptic curve
function ECPoint(x,y) {
    this.x = x;
    this.y = y;
}

// constructor
function EllipticCurveSecp256k1(  ) {
    // Secp256k1 parameters :

    // G	elliptic curve base point, a point on the curve that generates a subgroup of large prime order P
    //      y^{2}=x^{3}+ax+b
    var gx = BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    var gy = BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");     
    this.G = new ECPoint( gx, gy );
    this.a = BigInt("0")    
    this.b = BigInt("7")
    // Modulo for point addition
    this.N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    this.Corps = new Corps( this.N );
  
}

// Point doubking
EllipticCurveSecp256k1.prototype.pointDoubling = function ( point )  {
     r = (a + b ) % this.N;
     return r;
}

// Point Addition
EllipticCurveSecp256k1.prototype.pointAdding = function ( pointA, pointB )  {
    // lambda = (B.y - A.Y ) / (B.x -A.x )
    var lambdaN    = this.Corps.sub(pointB.y, pointA.y );
    var lambdaD    = this.Corps.sub(pointB.x, pointA.x );
    var invlambdaD = this.Corps.inversion( lambdaD );
    var lambda     = this.Corps.mult(lambdaN, invlambdaD );

    return r;
}