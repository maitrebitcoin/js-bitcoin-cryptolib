// elliptic curve

// point of an elliptic curve
class ECPoint {

constructor(x,y) {
    this.x = x;
    this.y = y;
}
// check if 2 points are equals 
equal( pointB )  {
    return    this.x == pointB.x 
           && this.y == pointB.y;
}
// check if a points is 0
isZero( pointB )  {
    return    this.x == 0
           && this.y == 0
}

}//class ECPoint {

class EllipticCurveSecp256k1 {    

// creation of the curve with the Secp256k1 paramèters
// see : https://en.bitcoin.it/wiki/Secp256k1
constructor() {
    // G	elliptic curve base point, a point on the curve that generates a subgroup of large prime order P
    //      y^{2}=x^{3}+ax+b
    //var gx = BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    //var gy = BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");     
    this.G = new ECPoint( 
             BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
             BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8") );
    this.a = BigInt("0")    
    this.b = BigInt("7")
    // Modulo for point addition
    this.N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    this.field = new GFied( this.N );
    // G must be on the curve
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

// 1 Point doubling
pointDouble( pointA )  {
    // formulas can be found here: 
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

    // 0 + 0 = 0
    if (pointA.isZero()) return new ECPoint(0, ry);    

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
pointAdd( pointA, pointB )  {
    // A + 0 = A
    if (pointB.isZero()) return pointA;
    // B + 0 = A
    if (pointA.isZero()) return pointB;    
    // if A == B, spécial case
    if (pointA.equal(pointB))
        return this.pointDouble(pointA, pointB);

    // formulas can be found here: 
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

    // lambda = (B.y - A.Y ) / (B.x -A.x )
    var lambdaN      = this.field.sub(pointB.y, pointA.y );
    var lambdaD      = this.field.sub(pointB.x, pointA.x );
    if (lambdaD == 0) // if A = -B
        return  new ECPoint( BigInt(0), BigInt(0) );
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

// Multiplication of a point by a big integer
// aka scalar multiplication
pointScalarMult( point, number ) {
    var pointResult = new ECPoint(0,0) 

     //  point * 2^N => 2G, 4G, 8G, 16G, etc.. 
     var point2powN = point
     while (number>0) {
      
        // if bit 0 is set
        var bit1 = number % BigInt(2)
        if (bit1 == BigInt(1)) {
            // r = r + point2powN
            pointResult = this.pointAdd( pointResult, point2powN )
        }
        // next bit
        number = number / BigInt(2)
        point2powN = this.pointDouble( point2powN )
     }

     console.assert( this.pointOnCurve(pointResult) || pointResult.isZero() );   
     return pointResult;
}

}// class EllipticCurveSecp256k1
