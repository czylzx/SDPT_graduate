#ifndef KUNLUN_CRYPTO_BIGINT_HPP_
#define KUNLUN_CRYPTO_BIGINT_HPP_

#include "std.inc"
#include "openssl.inc"
#include "context.hpp"

// wrapper class for openssl BIGNUM

class BigInt{
public:
    BIGNUM* bn_ptr;
    
    // constructor functions
    BigInt();
    BigInt(const BigInt& other);
    BigInt(const BIGNUM *other);
    BigInt(size_t number);

    // destuctor function
    ~BigInt();

    // arithmetic operations 
    
    // Returns a BigInt whose value is (- *this). Causes a check failure if the operation fails.
    BigInt Neg() const;

    // Returns a BigInt whose value is (*this + other). Causes a check failure if the operation fails.
    BigInt Add(const BigInt& other) const;

    // Returns a BigInt whose value is (*this - other). Causes a check failure if the operation fails.
    BigInt Sub(const BigInt& other) const;

    // Returns a BigInt whose value is (*this * other). Causes a check failure if the operation fails.
    BigInt Mul(const BigInt& other) const;

    // Returns a BigInt whose value is (*this / other).
    // Causes a check failure if the remainder != 0 or if the operation fails.
    BigInt Div(const BigInt& other) const;

    // Returns a BigInt whose value is *this / val, rounding towards zero.
    // Causes a check failure if the remainder != 0 or if the operation fails.
    BigInt DivAndTruncate(const BigInt& other) const;

    // Returns a BigInt whose value is (*this ^ exponent).
    // Causes a check failure if the operation fails.
    BigInt Exp(const BigInt& exponent) const;

    // Returns a BigInt whose value is (*this mod m).
    BigInt Mod(const BigInt& modulus) const;

    // Returns a BigInt whose value is (*this + other mod m).
    // Causes a check failure if the operation fails.
    BigInt ModAdd(const BigInt& other, const BigInt& modulus) const;

    // Returns a BigInt whose value is (*this - other mod m).
    // Causes a check failure if the operation fails.
    BigInt ModSub(const BigInt& other, const BigInt& modulus) const;

    // Returns a BigInt whose value is (*this * other mod m).
    // For efficiency, use Montgomery multiplication module if this is done multiple times with the same modulus.
    // Causes a check failure if the operation fails.
    BigInt ModMul(const BigInt& other, const BigInt& modulus) const;

    // Returns a BigInt whose value is (*this ^ exponent mod m).
    // Causes a check failure if the operation fails.
    BigInt ModExp(const BigInt& exponent, const BigInt& modulus) const;

    // Return a BigInt whose value is (*this ^ 2 mod m).
    // Causes a check failure if the operation fails.
    BigInt ModSquare(const BigInt& modulus) const;

    // Returns a BigInt whose value is (*this ^ -1 mod m).
    // Causes a check failure if the operation fails.
    BigInt ModInverse(const BigInt& modulus) const;

    // Returns r such that r^2 == *this mod p.
    // Causes a check failure if the operation fails.
    BigInt ModSquareRoot(const BigInt& modulus) const;

    // Computes -a mod m.
    // Causes a check failure if the operation fails.
    BigInt ModNegate(const BigInt& modulus) const;

    // Computes the greatest common divisor of *this and other.
    // Causes a check failure if the operation fails.
    BigInt GCD(const BigInt& other) const;

    
    // logic operations

    // Compares this BigInt with the specified BigInt.
    // Returns -1 if *this < other, 0 if *this == other and 1 if *this > other.
    int CompareTo(const BigInt& other) const;

    // Returns a BigInt whose value is (*this >> n).
    BigInt Lshift(int n) const; 

    // Returns a BigInt whose value is (*this << n).
    BigInt Rshift(int n) const;

    // operator overload

    inline BigInt& operator=(const BigInt& other) { BN_copy(this->bn_ptr, other.bn_ptr); return *this; }

    inline BigInt operator-() const { return this->Neg(); }

    inline BigInt operator+(const BigInt& b) const { return this->Add(b); }

    inline BigInt operator*(const BigInt& b) const { return this->Mul(b); }

    inline BigInt operator-(const BigInt& b) const { return this->Sub(b); }

    inline BigInt operator/(const BigInt& b) const { return this->Div(b); }

    inline BigInt& operator+=(const BigInt& b) { return *this = *this + b; }

    inline BigInt& operator*=(const BigInt& b) { return *this = *this * b; }

    inline BigInt& operator-=(const BigInt& b) { return *this = *this - b; }

    inline BigInt& operator/=(const BigInt& b) { return *this = *this / b; }

    inline bool operator==(const BigInt& b) const { return 0 == this->CompareTo(b); }

    inline bool operator!=(const BigInt& b) const { return !(*this == b); }

    inline bool operator<(const BigInt& b) const { return -1 == this->CompareTo(b); }

    inline bool operator>(const BigInt& b) const { return 1 == this->CompareTo(b); }

    inline bool operator<=(const BigInt& b) const { return this->CompareTo(b) <= 0; }

    inline bool operator>=(const BigInt& b) const { return this->CompareTo(b) >= 0; }

    inline BigInt operator%(const BigInt& modulus) const { return this->Mod(modulus); }

    inline BigInt operator>>(int n) { return this->Rshift(n); }

    inline BigInt operator<<(int n) { return this->Lshift(n); }

    inline BigInt& operator%=(const BigInt& b) { return *this = *this % b; }

    inline BigInt& operator>>=(int n) { return *this = *this >> n; }

    inline BigInt& operator<<=(int n) { return *this = *this << n; }



    // serialization and deserialization 

    /* save bigint object binary form */  
    void Serialize(std::ofstream &fout);

    /* recover bigint object from binary file */
    void Deserialize(std::ifstream &fin);

    friend std::ofstream &operator<<(std::ofstream &fout, const BigInt &A); 
    friend std::ifstream &operator>>(std::ifstream &fin, BigInt &A); 

    // attribute test routines

    inline int GetTheNthBit(size_t j) const;

    // returns 0 on error (if r is already shorter than n bits)
    // return value in that case should be the original value so there is no need to have error checking here.
    inline BigInt GetLastNBits(int n) const {
        BigInt result = *this;
        BN_mask_bits(result.bn_ptr, n);
        return result;
    }

    // returns the bit length of this BigInt.
    inline size_t GetBitLength() const { return BN_num_bits(this->bn_ptr); }
    inline size_t GetByteLength() const { return BN_num_bytes(this->bn_ptr); }

    inline bool IsBitSet(int n) const { return BN_is_bit_set(this->bn_ptr, n); }

    inline bool IsZero() const { return BN_is_zero(this->bn_ptr); }

    inline bool IsOne() const { return BN_is_one(this->bn_ptr); }

    inline bool IsNonNegative() const { 
        if (BN_is_negative(this->bn_ptr) == 1) return false; 
        else return true;
    }

    bool IsPrime(double prime_error_probability) const;

    bool IsSafePrime(double prime_error_probability) const;

    // print BigInt object, mode = {10, 16}
    void Print(int mode) const; 
    
    void Print(int mode, std::string note) const; 
};

// global bigint objects
const static BigInt bn_0(uint64_t(0)); 
const static BigInt bn_1(uint64_t(1)); 
const static BigInt bn_2(uint64_t(2)); 
const static BigInt bn_3(uint64_t(3)); 


// Copies the given BigInt.
BigInt::BigInt(){ 
    this->bn_ptr = BN_new(); 
}

BigInt::BigInt(const BigInt& other){
    this->bn_ptr = BN_new();
    BN_copy(this->bn_ptr, other.bn_ptr);
}

BigInt::BigInt(const BIGNUM *other){
    this->bn_ptr = BN_new(); 
    BN_copy(this->bn_ptr, other); 
}

// Creates a new BigInt object from the number.
BigInt::BigInt(size_t number){
    this->bn_ptr = BN_new();
    CRYPTO_CHECK(BN_set_word(this->bn_ptr, number));
}

BigInt::~BigInt(){
    BN_free(this->bn_ptr); 
}


// Converts this BigInt to a uint64_t value. Returns an INVALID_ARGUMENT
uint64_t ToInt64(const BigInt& a)
{
    uint64_t result = BN_get_word(a.bn_ptr);
    return result;
}

// Creates a new BigInt object from a bytes string.
BigInt BigIntFromByteString(const std::string& str)
{
    BigInt result; 
    BN_bin2bn(reinterpret_cast<const unsigned char*>(str.data()), str.size(), result.bn_ptr);
    return result; 
}
  
std::string BigIntToByteString(const BigInt& a)
{
    size_t LEN = a.GetByteLength();
    unsigned char buffer[LEN];
    memset(buffer, 0, LEN);  
    BN_bn2bin(a.bn_ptr, buffer);
    std::string result(reinterpret_cast<char *>(buffer), LEN); 
    return result;
}  


// Returns a BigInt whose value is (- *this).
// Causes a check failure if the operation fails.
BigInt BigInt::Neg() const {
    BigInt result = *this;
    BN_set_negative(result.bn_ptr, !BN_is_negative(result.bn_ptr));
    return result;
}

// Returns a BigInt whose value is (*this + val).
// Causes a check failure if the operation fails.
BigInt BigInt::Add(const BigInt& other) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_add(result.bn_ptr, this->bn_ptr, other.bn_ptr));
    return result;
}

// Returns a BigInt whose value is (*this - val).
// Causes a check failure if the operation fails.
BigInt BigInt::Sub(const BigInt& other) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_sub(result.bn_ptr, this->bn_ptr, other.bn_ptr));
    return result;
}

// Returns a BigInt whose value is (*this * val).
// Causes a check failure if the operation fails.
BigInt BigInt::Mul(const BigInt& other) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_mul(result.bn_ptr, this->bn_ptr, other.bn_ptr, bn_ctx));
    return result;
}

// Returns a BigInt whose value is (*this / val).
// Causes a check failure if the remainder != 0 or if the operation fails.
BigInt BigInt::Div(const BigInt& other) const {
    BigInt result;
    BigInt remainder;
    CRYPTO_CHECK(1 == BN_div(result.bn_ptr, remainder.bn_ptr, this->bn_ptr, other.bn_ptr, bn_ctx));
    if (BN_is_zero(remainder.bn_ptr)){
        std::cerr << "Use DivAndTruncate() instead of Div() if you want truncated division." << std::endl;  
    } 
    return result;
}

// Returns a BigInt whose value is *this / val, rounding towards zero.
// Causes a check failure if the remainder != 0 or if the operation fails.
BigInt BigInt::DivAndTruncate(const BigInt& other) const {
    BigInt result;
    BigInt remainder;
    CRYPTO_CHECK(1 == BN_div(result.bn_ptr, remainder.bn_ptr, this->bn_ptr, other.bn_ptr, bn_ctx));
    return result;
}

// Compares this BigInt with the specified BigInt.
// Returns -1 if *this < val, 0 if *this == val and 1 if *this > val.
int BigInt::CompareTo(const BigInt& other) const {
    return BN_cmp(this->bn_ptr, other.bn_ptr);
}

// Returns a BigInt whose value is (*this ^ exponent).
// Causes a check failure if the operation fails.
BigInt BigInt::Exp(const BigInt& exponent) const{
    BigInt result;
    CRYPTO_CHECK(1 == BN_exp(result.bn_ptr, this->bn_ptr, exponent.bn_ptr, bn_ctx));
    return result;
}

// Returns a BigInt whose value is (*this mod m).
BigInt BigInt::Mod(const BigInt& modulus) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_nnmod(result.bn_ptr, this->bn_ptr, modulus.bn_ptr, bn_ctx));
    return result;
}

// Returns a BigInt whose value is (*this + val mod m).
// Causes a check failure if the operation fails.
BigInt BigInt::ModAdd(const BigInt& other, const BigInt& modulus) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_mod_add(result.bn_ptr, this->bn_ptr, other.bn_ptr, modulus.bn_ptr, bn_ctx));
    return result;
}

// Returns a BigInt whose value is (*this - val mod m).
// Causes a check failure if the operation fails.
BigInt BigInt::ModSub(const BigInt& other, const BigInt& modulus) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_mod_sub(result.bn_ptr, this->bn_ptr, other.bn_ptr, modulus.bn_ptr, bn_ctx));
    return result;
}

// Returns a BigInt whose value is (*this * val mod m).
BigInt BigInt::ModMul(const BigInt& other, const BigInt& modulus) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_mod_mul(result.bn_ptr, this->bn_ptr, other.bn_ptr, modulus.bn_ptr, bn_ctx));
    return result;
}

// Returns a BigInt whose value is (*this ^ exponent mod m).
// Causes a check failure if the operation fails.
BigInt BigInt::ModExp(const BigInt& exponent, const BigInt& modulus) const {
    if (exponent.IsNonNegative() == false){
        std::cerr << "Cannot use a negative exponent in BigInt ModExp." << std::endl; 
    } 
    BigInt result;
    CRYPTO_CHECK(1 == BN_mod_exp(result.bn_ptr, this->bn_ptr, exponent.bn_ptr, modulus.bn_ptr, bn_ctx));

    return result;
}

// Return a BigInt whose value is (*this^2 mod m).
// Causes a check failure if the operation fails.
BigInt BigInt::ModSquare(const BigInt& modulus) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_mod_sqr(result.bn_ptr, this->bn_ptr, modulus.bn_ptr, bn_ctx));
    return result;
}

// Returns a BigInt whose value is (*this ^ -1 mod m).
// Causes a check failure if the operation fails.
BigInt BigInt::ModInverse(const BigInt& modulus) const {
    BigInt result;
    CRYPTO_CHECK(nullptr != BN_mod_inverse(result.bn_ptr, this->bn_ptr, modulus.bn_ptr, bn_ctx));
    return result;
}

// Returns r such that r^2 == *this mod p.
// Causes a check failure if the operation fails.
BigInt BigInt::ModSquareRoot(const BigInt& modulus) const {
    BigInt result;
    CRYPTO_CHECK(nullptr != BN_mod_sqrt(result.bn_ptr, bn_ptr, modulus.bn_ptr, bn_ctx));
    return result;
}

// Computes -a mod m.
// Causes a check failure if the operation fails.
BigInt BigInt::ModNegate(const BigInt& modulus) const {
    if (IsZero()) {
        return *this;
    }
    return modulus - Mod(modulus);
}

// Returns a BigInt whose value is (*this >> n).
BigInt BigInt::Lshift(int n) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_lshift(result.bn_ptr, this->bn_ptr, n));
    return result;
}

// Returns a BigInt whose value is (*this << n).
// Causes a check failure if the operation fails.
BigInt BigInt::Rshift(int n) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_rshift(result.bn_ptr, this->bn_ptr, n));
    return result;
}

// Computes the greatest common divisor of *this and val.
// Causes a check failure if the operation fails.
BigInt BigInt::GCD(const BigInt& other) const {
    BigInt result;
    CRYPTO_CHECK(1 == BN_gcd(result.bn_ptr, this->bn_ptr, other.bn_ptr, bn_ctx));
    return result;
}


// Returns False if the number is composite
// True if it is prime with an error probability of 1e-40, which gives at least 128 bit security.
bool BigInt::IsPrime(double prime_error_probability) const {
    int rounds = static_cast<int>(ceil(-log(prime_error_probability) / log(4)));
    return (1 == BN_is_prime_ex(this->bn_ptr, rounds, bn_ctx, nullptr));
}

bool BigInt::IsSafePrime(double prime_error_probability = 1e-40) const {
    return IsPrime(prime_error_probability) && ((*this - bn_1) / bn_2).IsPrime(prime_error_probability);
}


BigInt GenRandomBnLessThan(const BigInt& max) {
    BigInt result;
    CRYPTO_CHECK(1 == BN_rand_range(result.bn_ptr, max.bn_ptr));
    // BN_priv_rand_range(result.bn_ptr, max.bn_ptr);
    return result;
}

// Generates a cryptographically strong pseudo-random in the range [start, end).
BigInt GenRandomBnBetween(const BigInt& start, const BigInt& end) {
    if (start > end) {
        std::cerr << "provided range is invalid" << std::endl; 
    }
    return GenRandomBnLessThan(end - start) + start;
}

// Generates a cryptographically strong pseudo-random bytes of the specified length.
std::string GenRandBytes(int num_bytes) {
    if (num_bytes < 0){
        std::cerr << "num_bytes must be nonnegative, provided value was" << num_bytes << "."<<std::endl;
    } 
    std::unique_ptr<unsigned char[]> bytes(new unsigned char[num_bytes]);
    CRYPTO_CHECK(1 == RAND_bytes(bytes.get(), num_bytes));
    return std::string(reinterpret_cast<char*>(bytes.get()), num_bytes);
}

// Returns a BigNum that is relatively prime to the num and less than the num.
BigInt GenCoPrimeLessThan(const BigInt& num) {
    BigInt rand_num = GenRandomBnLessThan(num);
    while (rand_num.GCD(num) > bn_1) {
        rand_num = GenRandomBnLessThan(num);
    }
    return rand_num;
}

// Creates a safe prime BigNum with the given bit-length.
BigInt GenSafePrime(int prime_length) {
    BigInt result;
    CRYPTO_CHECK(1 == BN_generate_prime_ex(result.bn_ptr, prime_length, 1, nullptr, nullptr, nullptr));
    return result;
}

// Creates a prime BigNum with the given bit-length.
// Note: In many cases, we need to use a safe prime for cryptographic security to hold. 
// In this case, we should use GenerateSafePrime.
BigInt GenPrime(int prime_length) {
    BigInt result;
    CRYPTO_CHECK(1 == BN_generate_prime_ex(result.bn_ptr, prime_length, 0, nullptr, nullptr, nullptr));
    return result;
}


BigInt HashToBigInt(const std::string& input){
    unsigned char digest[SHA256_DIGEST_LENGTH]; 
    memset(digest, 0, SHA256_DIGEST_LENGTH); 
    
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);

    BigInt result; 
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, result.bn_ptr);
    return result; 
}


void BigInt::Print(int mode) const
{
    char *bn_str; 
    switch(mode){
        case 16: bn_str = BN_bn2hex(this->bn_ptr); break; 
        case 10: bn_str = BN_bn2dec(this->bn_ptr); break;
    }
    std::cout << bn_str << std::endl;
    OPENSSL_free(bn_str);
}

void BigInt::Print(int mode, std::string note) const
{
    std::cout << note << " = "; 
    this->Print(mode);
}


/* compute the jth bit of a big integer i (count from little endian to big endian) */
int BigInt::GetTheNthBit(size_t n) const
{
    BigInt a = *this;  
    a = a >> n;
    a = a.GetLastNBits(1);  

    int result; 
    if (a.IsOne()) return 1; 
    else return 0; 
}

// inline std::bitset BnToBinaryVector(const BigInt& a)
// {
//     size_t LEN  = a.BitLength(); 
//     bitset<LEN> vec_a; 
//     vector<uint64_t> bitvector(bn_length);
//     for(auto i = 0; i < LEN; i++){
//         if(a.GetBit(i) == 1) vec_a.set();
//     }

//     int res_length = bn_length%window_size;  
//     if (res_length != 0){
//         for(int i; i <= window_size - res_length; i++){
//             bitvector.push_back(0);
//         }
//     } 

//     int vec_length = bitvector.size()/window_size; 
//     vector<uint64_t> pow_vector(window_size);
//     for(int i = 0; i < window_size; i++){
//         pow_vector[i] = 1 << i;  
//     }

//     scalar_vec.resize(vec_length); 
//     for(int i = 0; i < vec_length; i++){
//         for(int j = 0; j < window_size; j++){
//             if(bitvector[i*window_size+j] == 1) scalar_vec[i] += pow_vector[j]; 
//         }
//     } 
// }

/* save bigint object binary form */  
void BigInt::Serialize(std::ofstream &fout)
{
    unsigned char buffer[BN_LEN];
    BN_bn2binpad(this->bn_ptr, buffer, BN_LEN);
    fout.write(reinterpret_cast<char *>(buffer), BN_LEN);   // write to outfile
}

/* recover bigint object from binary file */
void BigInt::Deserialize(std::ifstream &fin)
{
    char buffer[BN_LEN];
    fin.read(buffer, BN_LEN);
    BN_bin2bn(reinterpret_cast<unsigned char *>(buffer), BN_LEN, this->bn_ptr);
}

std::ofstream &operator<<(std::ofstream &fout, const BigInt& a)
{ 
    unsigned char buffer[BN_LEN];
    BN_bn2binpad(a.bn_ptr, buffer, BN_LEN);
    fout.write(reinterpret_cast<char *>(buffer), BN_LEN);   // write to output file
    return fout;            
}
 
std::ifstream &operator>>(std::ifstream &fin, BigInt &a)
{ 
    char buffer[BN_LEN];
    fin.read(buffer, BN_LEN);
    BN_bin2bn(reinterpret_cast<unsigned char *>(buffer), BN_LEN, a.bn_ptr); // red from input file
    return fin;            
}

#endif  // KUNLUN_CRYPTO_BIGINT_HPP_