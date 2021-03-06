/**
 ****************************************************** 
 * @file    ellipticurve.js 
 * @file    Elliptic curve with the Secp256k1 paramèters and associated types.
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see     https://en.bitcoin.it/wiki/Secp256k1
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

// A point on the elliptic curve
class ECPoint {

constructor(x,y) {
    this.x = x;
    this.y = y;
}
/**
 *  check if the point is equal to <pointB>
 *  @return {boolean}
 */
equal( pointB )  {
    return    this.x == pointB.x 
           && this.y == pointB.y;
}
/**
 * check if a points is (0,0)
 *  @return {boolean}
 */
isZero( pointB )  {
    return    this.x == 0
           && this.y == 0
}
/**
 *   convert the point to a 33 bytes buffer 
 * @return {string} 33 bytes buffer
 */
toBuffer() {
    var res = ""
    // the 1st byte si 0X02 or 0x03 depending of the parity of y
    // 0x02 for even / x03 for odd 
    if (this.y % BigInt(2) == BigInt(0)) // if y is even
        res  += '\x02'
    else 
        res  += '\x03'
    res += bigEndianBufferFromBigInt256( this.x )
    console.assert( res.length == 33)
    return res;
}

}//class ECPoint {

// The elliptic curve
class EllipticCurveSecp256k1 {    

// create a curve with the Secp256k1 paramèters
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
    this.field = new GField( this.N );
    // G must be on the curve
    console.assert( this.pointOnCurve(this.G) );  
}

/** 
 * check if a point is on the curve
 *  y^{2}=x^{3}+ax+b
 * @param {ECPoint} point
 * @return {boolean} true if a point is on the curve
 */
pointOnCurve( point )  {
    // calculates X^2 and Y^3
    var Y2 =  this.field.square( point.y );
    var X3 =  this.field.cube(   point.x );
    // simplication formula if a == 0
    return Y2 ==  this.field.add(X3,  this.b );
}
/** 
 *  Point doubling 
 * @param {ECPoint} pointA a point on the curve
 * @return {ECPoint} 2 * pointA
 */
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
/** 
 * 2 Point Addition
 * @param {ECPoint} pointA a point on the curve
 * @param {ECPoint} pointB a point on the curve, can be equal to pointA
 * @return {ECPoint} pointA + pointB
 */
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
/** 
 *  Multiplication of a point by a big integer (scalar multiplication)
 * @param {ECPoint} point a point on the curve
 * @param {BigInt} number 256 bits integer
 * @return {ECPoint} number * point
 */
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
/** 
 *  Multiplication of the generator point by a big integer (scalar multiplication)
 * @param {BigInt} number 256 bits integer
 * @return {ECPoint} number * generator point
 */
pointGeneratorScalarMult(  number ) {
 
     return this.pointScalarMult( this.G, number ) ;
}
/**
 *  calculates y from x 
 * 
 * @param  {BigInt}  x x coordinate of a point on the curve
 * @param  {boolean} resultIsEven  2 solutions are possible. yIsEven tells which one to choose from
 * 
 * @return {BigInt}  y coordinate of a point on the curve
 */
calculateYFromX( x, resultIsEven) {

    // y si so that y^2=x^3+7 => y = sqrt( x^3 + 7 )
    var x3 = this.field.cube(x)
    var x3plus7 = this.field.add(x3, BigInt(7) )
    // get the 2 roots
    var y1 = this.field.sqrt( x3plus7 )
    var y2 = this.field.negate( y1 )
    // test if y1 is even    
    var y1Even = (y1 % BigInt(2) == BigInt(0)) 
    // return y1 ou y2 depending on the requiered eveness
    if (y1Even == resultIsEven)
        return y1
    else
        return y2
}

}// class EllipticCurveSecp256k1
