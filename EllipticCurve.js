// elliptic curve

// point of an elliptic curve
function ECPoint(x,y) {
    this.x = x;
    this.y = y;
}
// check if 2 points are equals 
ECPoint.prototype.equal = function ( pointA, pointB )  {
    return    pointA.x == pointB.x 
           && pointA.y == pointB.y;
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
  
    console.assert( this.pointOnCurve(this.G) );  
}

// check if a point is on the curve
//  y^{2}=x^{3}+ax+b
EllipticCurveSecp256k1.prototype.pointOnCurve = function ( pointA )  {
    var Y2 =  this.Corps.square( pointA.y );
    var X3 =  this.Corps.cube(   pointA.x );
    // simplication furmula a == 0
    return Y2 ==  this.Corps.add(X3,  this.b );
}

// Point doubking
EllipticCurveSecp256k1.prototype.pointDoubling = function ( pointA )  {
    // formulas can be found here: 
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

    // lambda = (3* A.x^2 + a ) / (2 * A.y )
    var lambdaN      = this.Corps.square( pointA.x );
        lambdaN      = this.Corps.mult( BigInt(3), lambdaN );
    var lambdaD      = this.Corps.mult( BigInt(2), pointA.y );
    var invlambdaD   = this.Corps.inversion( lambdaD );
    var lambda       = this.Corps.mult(lambdaN, invlambdaD ); 

    // rx = L^2 - A.x - A.x
    var lambdaSquare =  this.Corps.square(lambda)
    var rx           =  this.Corps.sub(lambdaSquare, pointA.x)
        rx           =  this.Corps.sub(rx, pointA.x)
    // ry = L*( A.X - rx ) - A.Y
    var ry           =  this.Corps.mult(lambda, this.Corps.sub(pointA.x, rx) )
        ry           =  this.Corps.sub( ry, pointA.y )

    var pointRes = new ECPoint( rx, ry);    
    console.assert( this.pointOnCurve(pointRes) );
    return pointRes;
}

// Point Addition
EllipticCurveSecp256k1.prototype.pointAdding = function ( pointA, pointB )  {
    // if A == B, spécial case
    if (pointA.equal(pointB))
        return this.pointDoubling(pointA, pointB);

    // formulas can be found here: 
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

    // lambda = (B.y - A.Y ) / (B.x -A.x )
    var lambdaN      = this.Corps.sub(pointB.y, pointA.y );
    var lambdaD      = this.Corps.sub(pointB.x, pointA.x );
    var invlambdaD   = this.Corps.inversion( lambdaD );
    var lambda       = this.Corps.mult(lambdaN, invlambdaD );
    // rx = L^2 - A.x - B.x
    var lambdaSquare =  this.Corps.square(lambda)
    var rx           =  this.Corps.sub(lambdaSquare, pointA.x)
        rx           =  this.Corps.sub(rx, pointB.x)
    // ry = L*( A.X - rx ) - A.Y
    var ry           =  this.Corps.mult(lambda, this.Corps.sub(pointA.x, rx) )
        ry           =  this.Corps.sub( ry, pointA.y )

    var pointRes = ECPoint( rx, ry);
    console.assert( this.pointOnCurve(pointRes) );    
    return pointRes;    
}