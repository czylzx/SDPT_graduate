/***********************************************************************************
this hpp implements many_out_of_many proof and adopts the aadcp
***********************************************************************************/
#ifndef Any_OUT_OF_MANY_HPP_
#define ANY_OUT_OF_MANY_HPP_
#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../commitment/pedersen.hpp"
#include "../../utility/polymul.hpp"
#include "../bulletproofs/innerproduct_proof.hpp" 
#include <utility>
#include <iostream>

//!!!!!!!!!!!!!!!! if you want to invoke the Bulletproofs, must note taux and tx's order ! The order is reversed !!

namespace AnyOutOfMany{
    
using Serialization::operator<<; 
using Serialization::operator>>; 

// define structure of AnyOutOfManyProof
struct PP
{
    size_t com_len; // the length of the commitment  
    ECPoint g, h;
    ECPoint u; // used for inside innerproduct statement
    std::vector<ECPoint> vec_g, vec_h; // the pp of innerproduct part
};

std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.com_len;
    fout << pp.g << pp.h << pp.u;
    fout << pp.vec_g;
    fout << pp.vec_h;
    return fout;
}

std::ifstream &operator>>(std::ifstream &fin, PP& pp)
{
    fin >> pp.com_len;
    fin >> pp.g >> pp.h >> pp.u;
    pp.vec_g.resize(pp.com_len);
    pp.vec_h.resize(pp.com_len);
    fin >> pp.vec_g;
    fin >> pp.vec_h;
    return fin;  
}

struct Instance
{
    std::vector<ECPoint> vec_com;// the vector of the commitment, in APGC, it may refer to the pk or the elgamal cipher.
    BigInt k;
};
struct Witness
{
    std::vector<BigInt> vec_s;
    std::vector<BigInt> vec_b;
};

// define structure of AnyOutOfManyProof
struct Proof
{
    ECPoint A, S, T1, T2;
    ECPoint E; // E = init message for P^{y^{N} \circ b}
    BigInt taux, mu, tx; // tx = <l,r>
    BigInt fs;
    InnerProduct::Proof ip_proof;
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.A << proof.S << proof.T1 << proof.T2 << proof.E;
    fout << proof.taux << proof.mu << proof.tx << proof.fs;
    fout << proof.ip_proof;
    return fout; 
}

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.A >> proof.S >> proof.T1 >> proof.T2 >> proof.E;
    fin >> proof.taux >> proof.mu >> proof.tx >> proof.fs;
    fin >> proof.ip_proof;
    return fin; 
}

/* generate a^n = (a^0, a^1, a^2, ..., a^{n-1}) */ 
std::vector<BigInt> GenBigIntPowerVector(size_t LEN, const BigInt &a)
{
    std::vector<BigInt> vec_result(LEN);
    vec_result[0] = BigInt(bn_1); 
    for (auto i = 1; i < LEN; i++){
        vec_result[i] = (vec_result[i-1] * a) % order; // result[i] = result[i-1]*a % order
    }
    return vec_result; 
}

void PrintProof(Proof &proof)
{
    proof.A.Print("proof.A"); 
    proof.S.Print("proof.S"); 
    proof.T1.Print("proof.T1");  
    proof.T2.Print("proof.T2"); 
    proof.E.Print("proof.E");
    proof.taux.Print("proof.taux"); 
    proof.mu.Print("proof.mu"); 
    proof.tx.Print("proof.tx"); 
    InnerProduct::PrintProof(proof.ip_proof); 
}

PP Setup(size_t com_len, ECPoint g, ECPoint h)
{
    PP pp;
    pp.com_len = com_len;
    pp.g = g;
    pp.h = h;
    pp.u = GenRandomGenerator();
    pp.vec_g = GenRandomECPointVector(com_len);
    pp.vec_h = GenRandomECPointVector(com_len);

    return pp;
}

void Prove(PP &pp,Instance &instance, Witness &witness, Proof &proof , std::string &transcript_str)
{
    auto start_time = std::chrono::steady_clock::now();

    size_t LEN = pp.com_len;
    std::vector<BigInt> vec_aL(LEN);
    std::vector<BigInt> vec_aR(LEN);

    std::vector<BigInt> vec_1_power(LEN, bn_1); // vec_unary = 1^n

    vec_aL = witness.vec_b;

    vec_aR = BigIntVectorModSub(vec_aL, vec_1_power,  BigInt(order)); // Eq (42) -- aR = aL - 1^n
   
    BigInt alpha = GenRandomBigIntLessThan(order);

    std::vector<ECPoint> vec_A(2*LEN+1);
    std::copy(pp.vec_g.begin(), pp.vec_g.end(), vec_A.begin());
    std::copy(pp.vec_h.begin(), pp.vec_h.end(), vec_A.begin()+LEN);
    vec_A[2*LEN] = pp.u;

    std::vector<BigInt> vec_a(2*LEN+1);
    std::copy(vec_aL.begin(), vec_aL.end(), vec_a.begin());
    std::copy(vec_aR.begin(), vec_aR.end(), vec_a.begin()+LEN);
    vec_a[2*LEN] = alpha;

    proof.A = ECPointVectorMul(vec_A, vec_a);

    // pick sL, sR from Z_p^n (choose blinding vectors sL, sR)
    std::vector<BigInt> vec_sL = GenRandomBigIntVectorLessThan(LEN, order); 
    std::vector<BigInt> vec_sR = GenRandomBigIntVectorLessThan(LEN, order); 
    
    // compute S = H^alpha g^aL h^aR (commitment to sL and sR)
    BigInt beta = GenRandomBigIntLessThan(order); 

    std::copy(vec_sL.begin(), vec_sL.end(), vec_a.begin()); 
    std::copy(vec_sR.begin(), vec_sR.end(), vec_a.begin()+LEN); 
    vec_a[2*LEN] = beta; 

    proof.S = ECPointVectorMul(vec_A, vec_a); 

    transcript_str += proof.A.ToByteString(); 
    BigInt y = Hash::StringToBigInt(transcript_str);

    BigInt y_inverse = y.ModInverse(order);

    std::vector<BigInt> vec_y_inverse_power = GenBigIntPowerVector(LEN, y_inverse); // y^{-i+1}
 

    transcript_str += proof.S.ToByteString(); 
    BigInt z = Hash::StringToBigInt(transcript_str);

    BigInt z_square = z.ModSquare(order);
    BigInt z_cubic = (z * z_square) % order;
    
    size_t num = 1; // set the num, re-compute the z^{j+1} j \in [n]
    std::vector<BigInt> vec_adjust_z_power(num+1); // generate z^{j+1} j \in [n] 
    vec_adjust_z_power[0] = z; 
    for (auto j = 1; j <= num; j++){
        vec_adjust_z_power[j] = (z * vec_adjust_z_power[j-1]) % order; //pow(z, j+1, q); description below Eq (71)
    }  
    
    // compute l(X) 
    std::vector<BigInt> vec_z_unary(LEN, z); // z \cdot 1^n
    std::vector<BigInt> vec_zz_temp = BigIntVectorModSub(vec_aL, vec_z_unary, BigInt(order)); // vec_t = aL - z1^n
    std::vector<BigInt> vec_y_power = GenBigIntPowerVector(LEN, y); // y^n
    std::vector<BigInt> poly_ll0 = BigIntVectorModProduct(vec_y_power, vec_zz_temp, BigInt(order)); // y^n(aL - z1^n)
    std::vector<BigInt> poly_ll1 = BigIntVectorModProduct(vec_y_power, vec_sL, BigInt(order)); //y^n sL X

    // compute r(X)     
    std::vector<BigInt> poly_rr0 = BigIntVectorModAdd(vec_aR, vec_z_unary, BigInt(order)); // aR + z1^n
    std::vector<BigInt> vec_zz_temp_y_inverse = BigIntVectorModScalar(vec_y_inverse_power, z_square, BigInt(order));
    poly_rr0 = BigIntVectorModAdd(poly_rr0, vec_zz_temp_y_inverse, BigInt(order)); // aR + z1^n + z^2 y^{-i+1}
    
    std::vector<BigInt> poly_rr1(LEN);
    poly_rr1.assign(vec_sR.begin(), vec_sR.end());

    // compute t(X) 
    BigInt t0 = BigIntVectorModInnerProduct(poly_ll0, poly_rr0, BigInt(order)); 
    BigInt bn_temp1 = BigIntVectorModInnerProduct(poly_ll1, poly_rr0, BigInt(order)); 
    BigInt bn_temp2 = BigIntVectorModInnerProduct(poly_ll0, poly_rr1, BigInt(order));
    BigInt t1 = (bn_temp1 + bn_temp2) % BigInt(order);  
    BigInt t2 = BigIntVectorModInnerProduct(poly_ll1, poly_rr1, BigInt(order)); 

    // P picks tau1 and tau2
    BigInt tau1 = GenRandomBigIntLessThan(order); 
    BigInt tau2 = GenRandomBigIntLessThan(order); 
    
    vec_A.clear(); vec_A = {pp.g, pp.h};
    
    vec_a.clear(); vec_a = {t1, tau1};  
    proof.T1 = ECPointVectorMul(vec_A, vec_a); //pp.g * tau1 + pp.h * t1; mul(tau1, pp.g, t1, pp.h);
    
    vec_a.clear(); vec_a = {t2, tau2};  
    proof.T2 = ECPointVectorMul(vec_A, vec_a); //pp.g * tau2 + pp.h * t2; mul(tau2, pp.g, t2, pp.h);    

    // compute the challenge x
    transcript_str += proof.T1.ToByteString() + proof.T2.ToByteString(); 
    BigInt x = Hash::StringToBigInt(transcript_str); 

    BigInt x_square = x.ModSquare(order);   

    // compute the value of l(x) and r(x) at point x
    vec_zz_temp = BigIntVectorModScalar(poly_ll1, x, BigInt(order));
    std::vector<BigInt> llx = BigIntVectorModAdd(poly_ll0, vec_zz_temp, BigInt(order));

    vec_zz_temp = BigIntVectorModScalar(poly_rr1, x, BigInt(order)); 
    std::vector<BigInt> rrx = BigIntVectorModAdd(poly_rr0, vec_zz_temp, BigInt(order)); 
;
    proof.tx = BigIntVectorModInnerProduct(llx, rrx, BigInt(order));    

    proof.E = ECPointVectorMul(instance.vec_com, poly_ll1); // E = \prod_{i=1}^{n} P_i^{{y^N} \circ b_i}
    BigInt rs = GenRandomBigIntLessThan(order);
    proof.E = proof.E + pp.g * (-rs); // E = E + com(0, -rs)

    // compute taux
    proof.taux = (tau1 * x + tau2 * x_square) % order; //proof.taux = tau2*x_square + tau1*x; 

    // compute proof.mu = (alpha + beta*x) %q;  
    proof.mu = (alpha + beta * x) % order; 
    proof.fs = bn_0;

    size_t k = witness.vec_s.size();
    size_t j = 0;
    for(auto i = 0; i < LEN; i++){
        if(witness.vec_b[i] == bn_1){
            proof.fs = (proof.fs + witness.vec_s[j] * vec_y_power[i] ) % order;
            j++;
        }
    }
    
    // addtional check
    if(j != k)
    {
        std::cerr << "Error: the size of witness.vec_s is not equal to the size of witness.vec_b" << std::endl;
        std::cout<<"k = "<<k<<std::endl;
        PrintBigIntVector(witness.vec_s, "witness.vec_s");
        PrintBigIntVector(witness.vec_b, "witness.vec_b");
        std::cout<<"j = "<<j<<std::endl;
    }
    proof.fs = (rs * x + proof.fs) % order;

    // transmit llx and rrx via inner product proof
    InnerProduct::PP ip_pp = InnerProduct::Setup(LEN, false); 
    ip_pp.vec_g.resize(LEN); 
    std::vector<ECPoint> com_new_g(LEN);
    com_new_g.assign(instance.vec_com.begin(), instance.vec_com.end());
    std::copy(pp.vec_g.begin(), pp.vec_g.begin()+LEN, ip_pp.vec_g.begin()); // ip_pp.vec_g = pp.vec_g
    ip_pp.vec_g = ECPointVectorProduct(pp.vec_g, vec_y_inverse_power);  // ip_pp.vec_g = vec_g_new

    ip_pp.vec_g = ECPointVectorAdd(ip_pp.vec_g, com_new_g); // ip_pp.vec_g = vec_g_new + com_new

    ip_pp.vec_h.resize(LEN); 

    std::copy(pp.vec_h.begin(), pp.vec_h.begin()+LEN, ip_pp.vec_h.begin()); 

    transcript_str += x.ToByteString();  
    BigInt e = Hash::StringToBigInt(transcript_str);   

    InnerProduct::Witness ip_witness;
    ip_witness.vec_a = llx; 
    ip_witness.vec_b = rrx; 

    InnerProduct::Instance ip_instance;
    ip_pp.u = pp.u * e; //ip_pp.u = u^e 

    vec_A.resize(2*LEN); 
    std::copy(ip_pp.vec_g.begin(), ip_pp.vec_g.end(), vec_A.begin()); 
    std::copy(ip_pp.vec_h.begin(), ip_pp.vec_h.end(), vec_A.begin()+LEN); 

    vec_a.resize(2*LEN); 
    std::copy(ip_witness.vec_a.begin(), ip_witness.vec_a.end(), vec_a.begin()); 
    std::copy(ip_witness.vec_b.begin(), ip_witness.vec_b.end(), vec_a.begin()+LEN); 

    ip_instance.P = ECPointVectorMul(vec_A, vec_a);  
    ip_instance.P = ip_instance.P + ip_pp.u * proof.tx; // P = A + S^x + h^{-mu} u^tx

    InnerProduct::Prove(ip_pp, ip_instance, ip_witness, transcript_str, proof.ip_proof); 

    #ifdef DEBUG
        std::cout << "Any out of many Proof Generation Finishes >>>" << std::endl; 
    #endif
    
}

bool Verify(PP &pp, Instance &instance, Proof &proof, std::string &transcript_str)
{
    bool Validity; // variables for checking results
    std::vector<bool> vec_condition(2,false);

    transcript_str += proof.A.ToByteString(); 
    BigInt y = Hash::StringToBigInt(transcript_str);  //recover the challenge y
    BigInt y_inverse = y.ModInverse(order);  
    
    transcript_str += proof.S.ToByteString(); 
    BigInt z = Hash::StringToBigInt(transcript_str); // recover the challenge z

    BigInt z_minus = z.ModNegate(order); 
    BigInt z_square = z.ModSquare(order); // (z*z)%q; 
    BigInt z_cubic = (z * z_square) % order; // maybe it will be unused

    transcript_str += proof.T1.ToByteString() + proof.T2.ToByteString(); 
    BigInt x = Hash::StringToBigInt(transcript_str); 
    BigInt x_square = x.ModSquare(order);  // (x*x)%q;  //recover the challenge x from PI

    transcript_str += x.ToByteString(); 
    BigInt e = Hash::StringToBigInt(transcript_str);  // play the role of x_u

    size_t n = 1;
    size_t LEN = pp.com_len * n; // l = nm 
    std::vector<BigInt> vec_1_power(LEN, bn_1); // vec_unary = 1^n
    std::vector<BigInt> vec_short_1_power(pp.com_len, bn_1);  
    std::vector<BigInt> vec_y_power = GenBigIntPowerVector(LEN, y); 

    std::vector<BigInt> vec_adjust_z_power(n+1); // generate z^{j+2} j \in [n]
    vec_adjust_z_power[0] = z; 
    for (auto j = 1; j <= n; j++){
        vec_adjust_z_power[j] = (z * vec_adjust_z_power[j-1]) % order; 
    }  

    // compute sum_{j=1^m} z^{j+2}
    BigInt sum_z = bn_0; 
    for (auto j = 1; j <= n; j++){
        sum_z += vec_adjust_z_power[j]; 
    }
    sum_z = (sum_z * z) % order;  

    // compute delta_yz 
    BigInt bn_temp1 = BigIntVectorModInnerProduct(vec_1_power, vec_y_power, BigInt(order)); 
    BigInt bn_c0 = z.ModSub(z_square, order); // z
    bn_temp1 = bn_c0 * bn_temp1 % order; 
    BigInt delta_yz = bn_temp1 - z_cubic * BigInt(LEN) % order; 
    delta_yz = (delta_yz + order ) % order;

    // check  
    ECPoint LEFT = pp.g * proof.tx + pp.h * proof.taux;  // LEFT = g^{\taux} h^\hat{t}

    std::vector<ECPoint> vec_A(4);
    std::vector<BigInt> vec_a(4);
    vec_A[0] = pp.g, vec_A[1] = proof.T1, vec_A[2] = proof.T2, vec_A[3] = pp.g;
    vec_a[0] = delta_yz, vec_a[1] = x, vec_a[2] = x_square, vec_a[3] = z_square * instance.k % order;

    ECPoint RIGHT = ECPointVectorMul(vec_A, vec_a);  // RIGHT =  g^{\delta_yz} T_1^x T_2^{x^2} 

    vec_condition[0] = (LEFT == RIGHT); 

    // using Inner Product Argument
    InnerProduct::PP ip_pp = InnerProduct::Setup(LEN, false); 

    ip_pp.vec_g.resize(LEN); 
    std::copy(pp.vec_g.begin(), pp.vec_g.begin()+LEN, ip_pp.vec_g.begin()); // ip_pp.vec_g = pp.vec_g

    ip_pp.vec_h.resize(LEN); 
    std::copy(pp.vec_h.begin(), pp.vec_h.begin()+LEN, ip_pp.vec_h.begin()); 
    std::vector<BigInt> vec_y_inverse_power = GenBigIntPowerVector(LEN, y_inverse); // y^n
    std::vector<ECPoint> com_new(LEN);
    std::vector<ECPoint> vec_g_new(LEN);
    com_new.assign(instance.vec_com.begin(), instance.vec_com.end());
    ip_pp.vec_g = ECPointVectorProduct(ip_pp.vec_g, vec_y_inverse_power);  // ip_pp.vec_g = vec_g_new
    vec_g_new = ip_pp.vec_g;
    ip_pp.vec_g = ECPointVectorAdd(ip_pp.vec_g, com_new); // ip_pp.vec_g = vec_g_new + com_new

    InnerProduct::Instance ip_instance;
    ip_pp.u = pp.u * e; // u = u^e 
    
    vec_A.resize(3*ip_pp.VECTOR_LEN+5); 
    std::copy(pp.vec_g.begin(), pp.vec_g.end(), vec_A.begin());
    std::copy(pp.vec_h.begin(), pp.vec_h.end(), vec_A.begin()+ip_pp.VECTOR_LEN);
    std::copy(instance.vec_com.begin(), instance.vec_com.end(), vec_A.begin()+2*ip_pp.VECTOR_LEN);

    vec_A[3*ip_pp.VECTOR_LEN] = proof.A; 
    vec_A[3*ip_pp.VECTOR_LEN+1] = proof.S; 
    vec_A[3*ip_pp.VECTOR_LEN+2] = pp.g; 
    vec_A[3*ip_pp.VECTOR_LEN+3] = pp.u; 
    vec_A[3*ip_pp.VECTOR_LEN+4] = proof.E;

    vec_a.resize(3*ip_pp.VECTOR_LEN+5);

    //we need to simplify the below code
    std::vector<BigInt> vec_z_minus_unary(LEN, z_minus);
    std::vector<BigInt> vec_z(LEN, z);
    std::vector<BigInt> vec_rr = BigIntVectorModScalar(vec_y_power, z, BigInt(order)); // z y^n
    std::vector<BigInt> vec_zz_P = BigIntVectorModScalar(vec_y_power, z_minus, BigInt(order)); // -z y^n
    std::vector<BigInt> vec_z_plus = BigIntVectorModScalar(vec_y_inverse_power, z_square, BigInt(order)); 
    vec_z = BigIntVectorModAdd(vec_z, vec_z_plus, BigInt(order)); // z + z^2 y^{-i+1}

    std::move(vec_z_minus_unary.begin(), vec_z_minus_unary.end(), vec_a.begin());
    std::move(vec_z.begin(), vec_z.end(), vec_a.begin() + ip_pp.VECTOR_LEN); // LEFT += g^{1 z^n}
    std::move(vec_zz_P.begin(), vec_zz_P.end(), vec_a.begin()+2*ip_pp.VECTOR_LEN); 
     
    vec_a[3*ip_pp.VECTOR_LEN] = bn_1; 
    vec_a[3*ip_pp.VECTOR_LEN+1] = x; 
    vec_a[3*ip_pp.VECTOR_LEN+2] = proof.fs; 
    vec_a[3*ip_pp.VECTOR_LEN+3] = -proof.mu; 
    vec_a[3*ip_pp.VECTOR_LEN+4] = x;

    ip_instance.P = ECPointVectorMul(vec_A, vec_a);  // set P_new = A + S^x + h^{-mu} u^tx  
    ip_instance.P = ip_instance.P + ip_pp.u * proof.tx; // P_new = P_new + E
    
    vec_condition[1] = InnerProduct::Verify(ip_pp, ip_instance, transcript_str, proof.ip_proof); 

    Validity = vec_condition[0] && vec_condition[1];     
    #ifdef DEBUG
    for(auto i = 0; i < 2; i++){
    std::cout << std::boolalpha << "Condition "<< std::to_string(i) <<" (Any out of many proof) = " 
                << vec_condition[i] << std::endl; 
    }
    if (Validity){ 
        std::cout<< "Any out of many Proof Accepts >>>" << std::endl; 
    }
    else{
        std::cout<< "Any out of many Proof Rejects >>>" << std::endl; 
    }
    #endif

    return Validity;

}

}
#endif