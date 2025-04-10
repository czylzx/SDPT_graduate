#define DEBUG

#include "../zkp/nizk/nizk_solvent_any_out_of_many.hpp"
#include "../crypto/setup.hpp"
#include "../commitment/pedersen.hpp"
#include "../pke/twisted_exponential_elgamal.hpp"


void test_any_out_of_many(size_t N_max, size_t N_sender)
{
    PrintSplitLine('-');  
    std::cout << "begin the test of solvent_any_out_of_many.hpp >>>" << std::endl; 

    TwistedExponentialElGamal::PP pp_enc = TwistedExponentialElGamal::Setup(32, 7); 

    Solvent4UTXO::PP pp;
   
    Solvent4UTXO::Instance instance;
    Solvent4UTXO::Witness witness;
    Solvent4UTXO::Proof proof;
    

    pp=Solvent4UTXO::Setup(N_max, pp_enc.g, pp_enc.h);
  
    std::vector<BigInt> vec_s(N_sender);
    std::vector<BigInt> vec_b(N_max);
    //instance.k = BigInt(N_sender);

    // size_t sum_b = 0;
    // for(auto i = 0; i < N_max; i++)
    // {
    //     srand(time(0));
    //     size_t random_b = rand() % 2;
    //     if(random_b == 0)
    //     {
    //         if(N_sender-sum_b >= N_max -i)
    //         {
    //             vec_b[i] = bn_1;
    //             sum_b++;
    //         }
    //         else
    //         {
    //             vec_b[i] = bn_0;
    //         }
    //         //vec_b[i] = bn_0;
    //     }
    //     else
    //     {
    //         if(sum_b < N_sender)
    //         {
    //             vec_b[i] = bn_1;
    //             sum_b++;
    //         }
    //         else
    //         {
    //             vec_b[i] = bn_0;
    //         }      
    //     }  
    // }
    vec_b = {bn_0, bn_0, bn_1, bn_0, bn_1, bn_0, bn_0, bn_0};
    for(auto i = 0; i < N_sender; i++)
    {
        vec_s[i] = GenRandomBigIntLessThan(order);
    }
    witness.vec_s = vec_s;
    witness.vec_b = vec_b;
    PrintBigIntVector(witness.vec_s, "witness.vec_s");
    PrintBigIntVector(witness.vec_b, "witness.vec_b");
    size_t j = 0;
    for(auto i = 0; i < N_max; i++)
    {
        if(vec_b[i] == bn_1)
        {
            //instance.vec_com.push_back(Pedersen::Commit(pp_com, value, vec_s[j]));
            instance.vec_com.push_back(pp_enc.g * vec_s[j]);
            j++;
        }
        else
        {
            BigInt random_value = GenRandomBigIntLessThan(order);
            //instance.vec_com.push_back(Pedersen::Commit(pp_com, value, random_value));
            instance.vec_com.push_back(pp_enc.g * random_value);
        }
        
    }

    std::string transcript_str = "";
    Solvent4UTXO::Prove(pp, instance, witness, proof, transcript_str);

    transcript_str = "";
    bool testval = Solvent4UTXO::Verify(pp, instance, proof, transcript_str);
}

int main()
{
    CRYPTO_Initialize(); 
    size_t N_max = 8;
    size_t N_sender = 2;
   
    test_any_out_of_many(N_max, N_sender);

    CRYPTO_Finalize(); 

    return 0; 
}