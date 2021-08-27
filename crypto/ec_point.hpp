#ifndef KUNLUN_EC_POINT_HPP_
#define KUNLUN_EC_POINT_HPP_


#include "std.inc"
#include "openssl.inc"
#include "ec_group.hpp"
#include "bigint.hpp"
#include "../common/routines.hpp"

class BigInt;

// C++ Wrapper class for openssl EC_POINT.
class ECPoint {
public:
    EC_POINT* point_ptr; 
    
    // constructor functions
    
    ECPoint(); 
    ECPoint(const ECPoint& other);
    ECPoint(const EC_POINT* &other);
    
    // Creates an ECPoint object with given x, y affine coordinates.
    ECPoint(const BigInt& x, const BigInt& y);

    // Returns an ECPoint that is a copy of this.
    void Clone(const ECPoint& other) const;

    void SetInfinity(); 

    // EC point group operations
    
    // Returns an ECPoint whose value is (this * scalar).
    ECPoint Mul(const BigInt& scalar) const;

    // Returns an ECPoint whose value is (this + other).
    ECPoint Add(const ECPoint& other) const;

    // Returns an ECPoint whose value is (- this), the additive inverse of this.
    ECPoint Invert() const;

    // Returns an ECPoint whose value is (this - other).
    ECPoint Sub(const ECPoint& other) const; 


    // attribute check operations

    // Returns "true" if the value of this ECPoint is the point-at-infinity.
    // (The point-at-infinity is the additive unit in the EC group).
    bool IsPointAtInfinity() const;
    bool IsOnCurve() const; 
    bool IsValid() const;
    bool IsAtInfinity() const;  

    // Returns true if this equals point, false otherwise.
    bool CompareTo(const ECPoint& point) const;


    inline ECPoint& operator=(const ECPoint& other) { EC_POINT_copy(this->point_ptr, other.point_ptr); return *this; }

    inline bool operator==(const ECPoint& other) const{ return this->CompareTo(other); }

    inline bool operator!=(const ECPoint& other) const{ return !this->CompareTo(other);}

    inline ECPoint operator-() const { return this->Invert(); }

    inline ECPoint operator+(const ECPoint& other) const { return this->Add(other); }

    inline ECPoint operator*(const BigInt& scalar) const { return this->Mul(scalar); }

    inline ECPoint operator-(const ECPoint& other) const { return this->Sub(other); }

    inline ECPoint& operator+=(const ECPoint& other) { return *this = *this + other; }

    inline ECPoint& operator*=(const BigInt& scalar) { return *this = *this * scalar; }

    inline ECPoint& operator-=(const ECPoint& other) { return *this = *this - other; }

    void Print() const;

    void Print(std::string note) const;  

    void Serialize(std::ofstream &fout); 

    void Deserialize(std::ifstream &fin);

    std::string ECPointToByteString() const;

    std::string ThreadSafe_ECPointToByteString() const;

    friend std::ofstream &operator<<(std::ofstream &fout, const ECPoint &A); 
 
    friend std::ifstream &operator>>(std::ifstream &fin, ECPoint &A); 
};
 

ECPoint::ECPoint(){
    this->point_ptr = EC_POINT_new(group);
}

ECPoint::ECPoint(const ECPoint& other){
    this->point_ptr = EC_POINT_new(group);
    EC_POINT_copy(this->point_ptr, other.point_ptr);
}

ECPoint::ECPoint(const EC_POINT* &other){
    this->point_ptr = EC_POINT_new(group);
    EC_POINT_copy(this->point_ptr, other);
}

ECPoint::ECPoint(const BigInt& x, const BigInt& y){
    this->point_ptr = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates_GFp(group, this->point_ptr, x.bn_ptr, y.bn_ptr, bn_ctx);
}


ECPoint ECPoint::Mul(const BigInt& scalar) const {
    ECPoint ecp_result;
    if (1 != EC_POINT_mul(group, ecp_result.point_ptr, nullptr, this->point_ptr, scalar.bn_ptr, bn_ctx)) {
        std::cerr << "EC_POINT_mul failed:" << OpenSSLErrorString() << std::endl;
    }
    return ecp_result;
}

ECPoint ECPoint::Add(const ECPoint& other) const {
    ECPoint ecp_result;
    if (1 != EC_POINT_add(group, ecp_result.point_ptr, this->point_ptr, other.point_ptr, bn_ctx)) {
        std::cerr << "EC_POINT_add failed:" << OpenSSLErrorString() << std::endl;
    }
    return ecp_result; 
}

ECPoint ECPoint::Invert() const {
    // Create a copy of this.
    ECPoint ecp_result = (*this);  
    if (1 != EC_POINT_invert(group, ecp_result.point_ptr, bn_ctx)) {
        std::cerr <<"EC_POINT_invert failed:" << OpenSSLErrorString() << std::endl;
    }
    return ecp_result; 
}

ECPoint ECPoint::Sub(const ECPoint& other) const { 
    ECPoint ecp_result = other.Invert(); 
    if (1 != EC_POINT_add(group, ecp_result.point_ptr, this->point_ptr, ecp_result.point_ptr, bn_ctx)) {
        std::cerr << "EC_POINT_sub failed:" << OpenSSLErrorString() << std::endl;
    }
    return ecp_result; 
}

void ECPoint::Clone(const ECPoint& other) const {
    if (1 != EC_POINT_copy(this->point_ptr, other.point_ptr)) {
        std::cerr << "EC_POINT_copy failed:" << OpenSSLErrorString() << std::endl;
    }
}


bool ECPoint::IsAtInfinity() const {
    return EC_POINT_is_at_infinity(group, this->point_ptr);
}

// Returns true if the given point is in the group.
bool ECPoint::IsOnCurve() const {
    return (1 == EC_POINT_is_on_curve(group, this->point_ptr, bn_ctx));
}

// Checks if the given point is valid. Returns false if the point is not in the group or if it is the point is at infinity.
bool ECPoint::IsValid() const{
    if (!this->IsOnCurve() || this->IsAtInfinity()){
        return false;
    }
    return true;
}


bool ECPoint::CompareTo(const ECPoint& other) const{
    return (0 == EC_POINT_cmp(group, this->point_ptr, other.point_ptr, bn_ctx));
}

/* 
 *  non-class functions
*/

// Creates an ECPoint object with the given x, y affine coordinates.
ECPoint CreateECPoint(const BigInt& x, const BigInt& y){
    ECPoint ecp_result(x, y);
    if (!ecp_result.IsValid()) {
        std::cerr << "ECGroup::CreateECPoint(x,y) - The point is not valid." << std::endl;
    }
    return ecp_result;
}

ECPoint GetRandomGenerator(){
    ECPoint ecp_result = ECPoint(generator); 
    BigInt bn_order(order); 
    ecp_result = ecp_result * GenRandomBnBetween(bn_1, bn_order);
    return ecp_result; 
}

// Creates an ECPoint which is the identity.
ECPoint GetPointAtInfinity(){
    ECPoint ecp_result;
    if (EC_POINT_set_to_infinity(group, ecp_result.point_ptr) != 1) {
        std::cerr << "ECGroup::GetPointAtInfinity() - Could not get point at infinity." << std::endl;
    }
    return ecp_result;
}

bool IsSquare(const BigInt& q) {
    return q.ModExp(BigInt(curve_params_q), BigInt(curve_params_p)).IsOne();
}

bool TryHashToPoint(BigInt x, ECPoint& point) 
{
    BigInt y_square = (x.Exp(bn_3) + BigInt(curve_params_a) * x + BigInt(curve_params_b)).Mod(BigInt(curve_params_p));

    if (IsSquare(y_square)){
        BigInt y = y_square.ModSquareRoot(curve_params_p);
        if (y.IsBitSet(0)){
            point = CreateECPoint(x, y.ModNegate(curve_params_p));
        }
        point = CreateECPoint(x, y);
        return true; 
    }
    return false; 
}

ECPoint HashToPoint(const std::string& input) 
{
    ECPoint ecp_result; 

    BigInt p = BigInt(curve_params_p); 
    BigInt x = HashToBigInt(input);

    x = x.Mod(p);    
    while (true) {
        if (TryHashToPoint(x, ecp_result)) break; 
        x = HashToBigInt(BigIntToByteString(x));
    }

    return ecp_result;
}

void ECPoint::SetInfinity()
{
    this->Clone(GetPointAtInfinity());    
}

void ECPoint::Print() const
{
    char *ecp_str = EC_POINT_point2hex(group, this->point_ptr, POINT_CONVERSION_UNCOMPRESSED, NULL);
    std::cout << ecp_str << std::endl; 
    OPENSSL_free(ecp_str); 
}

// print an EC point with note
void ECPoint::Print(std::string note) const
{ 
    std::cout << note << " = "; 
    this->Print(); 
}

void ECPoint::Serialize(std::ofstream &fout)
{
    unsigned char buffer[POINT_LEN];
    EC_POINT_point2oct(group, this->point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, bn_ctx);
    // write to outfile
    fout.write(reinterpret_cast<char *>(buffer), POINT_LEN); 
}

void ECPoint::Deserialize(std::ifstream &fin)
{
    unsigned char buffer[POINT_LEN];
    fin.read(reinterpret_cast<char *>(buffer), POINT_LEN); 
    EC_POINT_oct2point(group, this->point_ptr, buffer, POINT_LEN, bn_ctx);
}

std::string ECPointToByteString(const ECPoint& A)
{
    unsigned char buffer[POINT_LEN]; 
    memset(buffer, 0, POINT_LEN); 

    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, bn_ctx);
    std::string result; 
    result.assign(reinterpret_cast<char *>(buffer), POINT_LEN);

    return result; 
}


std::ofstream &operator<<(std::ofstream &fout, const ECPoint &A)
{ 
    unsigned char buffer[POINT_LEN];
    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, BN_LEN+1, bn_ctx);
    // write to outfile
    fout.write(reinterpret_cast<char *>(buffer), POINT_LEN); 
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, ECPoint &A)
{ 
    unsigned char buffer[POINT_LEN];
    fin.read(reinterpret_cast<char *>(buffer), BN_LEN+1); 
    EC_POINT_oct2point(group, A.point_ptr, buffer, POINT_LEN, bn_ctx);
    return fin;            
}



inline void VectorMul(std::vector<ECPoint> &A, std::vector<BigInt> &scalar, ECPoint &result){
    if (A.size()!=scalar.size()){
        std::cerr << "vector size does not match" << std::endl; 
        return; 
    }
    size_t LEN = A.size(); 
    std::vector<EC_POINT*> vec_A(LEN); 
    std::vector<BIGNUM*> vec_scalar(LEN); 
    for(auto i = 0; i < LEN; i++){
        vec_A[i] = A[i].point_ptr; 
        vec_scalar[i] = scalar[i].bn_ptr;
    } 
    EC_POINTs_mul(group, result.point_ptr, nullptr, LEN, (const EC_POINT**)vec_A.data(), (const BIGNUM**)vec_scalar.data(), bn_ctx); 
}


/* Thread safe implementation for some functions */

std::string ThreadSafe_ECPointToByteString(const ECPoint& A)
{
    unsigned char buffer[POINT_LEN]; 
    memset(buffer, 0, POINT_LEN); 

    EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, nullptr);
    std::string ecp_str(reinterpret_cast<char *>(buffer), POINT_LEN);
    return ecp_str; 
}

inline void ThreadSafe_Mul(ECPoint &A, BigInt &scalar, ECPoint &result){
    EC_POINT_mul(group, result.point_ptr, nullptr, A.point_ptr, scalar.bn_ptr, nullptr); 
}

inline void ThreadSafe_Add(ECPoint &X, ECPoint &Y, ECPoint &result) 
{
    EC_POINT_add(group, result.point_ptr, X.point_ptr, Y.point_ptr, nullptr);  
}

inline void ThreadSafe_Sub(ECPoint &X, ECPoint &Y, ECPoint &result) 
{
    ECPoint Y_inverse = Y; 
    EC_POINT_invert(group, Y_inverse.point_ptr, nullptr); 
    EC_POINT_add(group, result.point_ptr, X.point_ptr, Y_inverse.point_ptr, nullptr);  
}


inline void ThreadSafe_VectorMul(std::vector<ECPoint> &A, std::vector<BigInt> &scalar, ECPoint &result){
    if (A.size()!=scalar.size()){
        std::cerr << "vector size does not match" << std::endl; 
        return; 
    }
    size_t LEN = A.size(); 
    std::vector<EC_POINT*> vec_A(LEN); 
    std::vector<BIGNUM*> vec_scalar(LEN); 
    for(auto i = 0; i < LEN; i++){
        vec_A[i] = A[i].point_ptr; 
        vec_scalar[i] = scalar[i].bn_ptr;
    } 
    EC_POINTs_mul(group, result.point_ptr, nullptr, LEN, (const EC_POINT**)vec_A.data(), (const BIGNUM**)vec_scalar.data(), nullptr); 
}


/* customized hash for ECPoint class */

namespace std
{
    template <> struct hash<ECPoint>
    {
        std::size_t operator()(const ECPoint& A) const
        { 
            return std::hash<std::string>{}(ThreadSafe_ECPointToByteString(A));
        }
    };
}




#endif  // KUNLUN_EC_POINT_HPP_





