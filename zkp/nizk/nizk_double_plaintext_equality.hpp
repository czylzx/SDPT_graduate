/***********************************************************************************
this hpp implements NIZKPoK for two twisited ElGamal ciphertexts 
encrypt the same message 
***********************************************************************************/
#ifndef KUNLUN_NIZK_PT2EQ_HPP_
#define KUNLUN_NIZK_PT2EQ_HPP_

#include "../../crypto/ec_point.hpp"
#include "../../crypto/hash.hpp"
#include "../../pke/twisted_exponential_elgamal.hpp"

namespace PlaintextEquality4Two{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define structure of PT_EQ_Proof 
struct PP
{
    ECPoint g; 
    ECPoint h;
};

// structure of instance (pk_1,...,pk_n, Xi = pk_i^r, Y = g^r h^v)
struct Instance
{
    ECPoint pk1, pk2;
    TwistedExponentialElGamal::CT ct1, ct2;  
};

// structure of witness 
struct Witness
{
    BigInt v; 
    BigInt r1, r2; 
};


// structure of proof 
struct Proof
{
    ECPoint A1, A2;
    ECPoint B; // P's first round message
    BigInt z1, z2, t;    // P's response in Zq
};

std::ofstream &operator<<(std::ofstream &fout, const Proof &proof)
{
    fout << proof.A1 << proof.A2;
    fout << proof.B << proof.z1 << proof.z2 << proof.t;
    return fout;
} 

std::ifstream &operator>>(std::ifstream &fin, Proof &proof)
{
    fin >> proof.A1 >> proof.A2;
    fin >> proof.B >> proof.z1 >> proof.z2 >> proof.t;
    return fin;
} 



void PrintInstance(Instance &instance)
{
   
} 

void PrintWitness(Witness &witness)
{
    
} 

void PrintProof(Proof &proof)
{
    PrintSplitLine('-'); 
    std::cout << "NIZKPoK for Plaintext Equality >>> " << std::endl; 

    proof.A1.Print("proof.A1");
    proof.A2.Print("proof.A2");
    proof.B.Print("proof.B");
    proof.z1.Print("proof.z1");
    proof.z2.Print("proof.z2");
    proof.t.Print("proof.t");
} 

std::string ProofToByteString(Proof &proof)
{
    std::string str;
    str += proof.A1.ToByteString();
    str += proof.A2.ToByteString();
    str += proof.B.ToByteString();
    str += proof.z1.ToHexString();
    str += proof.z2.ToHexString();
    str += proof.t.ToHexString();
    return str; 
} 


/* Setup algorithm */ 
PP Setup(TwistedExponentialElGamal::PP pp_enc)
{ 
    PP pp;
    pp.g = pp_enc.g;
    pp.h = pp_enc.h; 
    return pp;
}

// generate NIZK proof for Ci = Enc(pki, v; r) i={1,2,3} the witness is (r, v)
Proof Prove(PP &pp, Instance &instance, Witness &witness, std::string &transcript_str)
{    
    Proof proof; 
    // initialize the transcript with instance
    transcript_str += instance.pk1.ToByteString();
    transcript_str += instance.pk2.ToByteString();
    transcript_str += instance.ct1.X.ToByteString();
    transcript_str += instance.ct1.Y.ToByteString();
    transcript_str += instance.ct2.X.ToByteString();
    transcript_str += instance.ct2.Y.ToByteString();

    // generate the first round message

    BigInt a = GenRandomBigIntLessThan(order);
    proof.A1 = instance.pk1 * a;
    proof.A2 = instance.pk2 * a;
 
    BigInt b = GenRandomBigIntLessThan(order); 
    std::vector<ECPoint> vec_Base{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{a, b};
    proof.B = ECPointVectorMul(vec_Base, vec_x); // B = g^a h^b

    // update the transcript with the first round message
    transcript_str += proof.A1.ToByteString();
    transcript_str += proof.A2.ToByteString();
    transcript_str += proof.B.ToByteString();  
                     
    // compute the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // apply FS-transform to generate the challenge

    // compute the response 
    proof.z1 = (a + e * witness.r1) % order; // z = a+e*r mod q 
    proof.z2 = (a + e * witness.r2) % order; // z = a+e*r mod q
    proof.t = (b + e * witness.v) % order; // t = b+e*v mod q

    #ifdef DEBUG
        PrintProof(proof); 
    #endif

    return proof; 
}


// check NIZK proof PI for Ci = Enc(pki, m; r) the witness is (r1, r2, m)
bool Verify(PP &pp, Instance &instance, std::string &transcript_str, Proof &proof)
{
    // initialize the transcript with instance
    transcript_str += instance.pk1.ToByteString();
    transcript_str += instance.pk2.ToByteString();
    transcript_str += instance.ct1.X.ToByteString();
    transcript_str += instance.ct1.Y.ToByteString();
    transcript_str += instance.ct2.X.ToByteString();
    transcript_str += instance.ct2.Y.ToByteString();

    transcript_str += proof.A1.ToByteString();
    transcript_str += proof.A2.ToByteString();
    transcript_str += proof.B.ToByteString();  
    
    // compute the challenge
    BigInt e = Hash::StringToBigInt(transcript_str); // apply FS-transform to generate the challenge

    

    ECPoint LEFT, RIGHT; 
    bool vec_condition[4];

    LEFT = instance.pk1 * proof.z1; // pk1^{z1}
    RIGHT = proof.A1 + instance.ct1.X * e;  
    vec_condition[0] = (LEFT == RIGHT); //check pk1^z = A1 X1^e

    LEFT = instance.pk2 * proof.z2; // pk1^{z1}
    RIGHT = proof.A2 + instance.ct2.X * e;  
    vec_condition[1] = (LEFT == RIGHT); //check pk1^z = A1 X1^e

   
    std::vector<ECPoint> vec_base{pp.g, pp.h}; 
    std::vector<BigInt> vec_x{proof.z1, proof.t}; 
    LEFT = ECPointVectorMul(vec_base, vec_x); // g^z h^t
    RIGHT = proof.B + instance.ct1.Y * e; // B Y^e
    
    vec_condition[2] = (LEFT == RIGHT); // check g^z h^t = B Y^e

    vec_x[0] = proof.z2;
    LEFT = ECPointVectorMul(vec_base, vec_x); // g^z h^t
    RIGHT = proof.B + instance.ct2.Y * e; // B Y^e

    vec_condition[3] = (LEFT == RIGHT); // check g^z h^t = B Y^e

    bool Validity = true; 
    for(auto i = 0; i <=3 ; i++){
        if(vec_condition[i] == false) Validity = false;
    }

    #ifdef DEBUG
    for(auto i = 0; i <=3; i++){
        std::cout << std::boolalpha << "Condition "<< std::to_string(i) <<" (Plaintext Equality proof) = " 
                  << vec_condition[i] << std::endl; 
    }

    if (Validity){ 
        std::cout << "NIZK proof for " << std::to_string(3) 
                  << "-receivers twisted ElGamal plaintext equality accepts >>>" << std::endl; 
    } else {
        std::cout << "NIZK proof for " << std::to_string(3) 
                  << "-receivers twisted ElGamal plaintext equality rejects >>>" << std::endl; 
    }
    #endif

    return Validity;
}



}

#endif



