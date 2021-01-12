// elliptic curve

// point of an elliptic curve
function ECPoint(x,y) {
    this.x = x;
    this.y = y;
}
// check if 2 points are equals 
ECPoint.prototype.equal = function ( pointB )  {
    return    this.x == pointB.x 
           && this.y == pointB.y;
}

class EllipticCurveSecp256k1 {    

// constructor
constructor() {
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
    this.field = new GFied( this.N );
  
    console.assert( this.pointOnCurve(this.G) );  
}

// check if a point is on the curve
//  y^{2}=x^{3}+ax+b
pointOnCurve( pointA )  {
    var Y2 =  this.field.square( pointA.y );
    var X3 =  this.field.cube(   pointA.x );
    // simplication furmula a == 0
    return Y2 ==  this.field.add(X3,  this.b );
}

// 1 Point doubking
pointDoubling( pointA )  {
    // formulas can be found here: 
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

    // lambda = (3* A.x^2 + a ) / (2 * A.y )
    var lambdaN      = this.field.square( pointA.x );
        lambdaN      = this.field.mult( BigInt(3), lambdaN );
    var lambdaD      = this.field.mult( BigInt(2), pointA.y );
    var invlambdaD   = this.field.inversion( lambdaD );
    var lambda       = this.field.mult(lambdaN, invlambdaD ); 

    // rx = L^2 - A.x - A.x
    var lambdaSquare = this.field.square(lambda)
    var rx           = this.field.sub(lambdaSquare, pointA.x)
        rx           = this.field.sub(rx, pointA.x)
    // ry = L*( A.X - rx ) - A.Y
    var ry           = this.field.mult(lambda, this.field.sub(pointA.x, rx) )
        ry           = this.field.sub( ry, pointA.y )

    var pointRes = new ECPoint( rx, ry);    
    console.assert( this.pointOnCurve(pointRes) );
    return pointRes;
}

// 2 Point Addition
pointAdding( pointA, pointB )  {
    // if A == B, spécial case
    if (pointA.equal(pointB))
        return this.pointDoubling(pointA, pointB);

    // formulas can be found here: 
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

    // lambda = (B.y - A.Y ) / (B.x -A.x )
    var lambdaN      = this.field.sub(pointB.y, pointA.y );
    var lambdaD      = this.field.sub(pointB.x, pointA.x );
    var invlambdaD   = this.field.inversion( lambdaD );
    var lambda       = this.field.mult(lambdaN, invlambdaD );
    // rx = L^2 - A.x - B.x
    var lambdaSquare = this.field.square(lambda)
    var rx           = this.field.sub(lambdaSquare, pointA.x)
        rx           = this.field.sub(rx, pointB.x)
    // ry = L*( A.X - rx ) - A.Y
    var ry           = this.field.mult(lambda, this.field.sub(pointA.x, rx) )
        ry           = this.field.sub( ry, pointA.y )

    var pointRes = new ECPoint( rx, ry);
    console.assert( this.pointOnCurve(pointRes) );    
    return pointRes;    
}

}// class EllipticCurveSecp256k1
