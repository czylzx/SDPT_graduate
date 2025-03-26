/****************************************************************************
this hpp implements the SDPT functionality 
*****************************************************************************/
#ifndef SDPT_UTXO_HPP_
#define SDPT_UTXO_HPP_

#include "../pke/twisted_exponential_elgamal.hpp"        // implement twisted ElGamal PKE
#include "../zkp/bulletproofs/bullet_proof.hpp"          // implement Bulletproof
#include "../zkp/nizk/nizk_solvent_any_out_of_many.hpp" // implement any out of many proof
#include "../zkp/nizk/nizk_plaintext_knowledge.hpp"     // NIZKPoK for plaintext knowledge
#include "../zkp/nizk/nizk_double_plaintext_equality.hpp" // NIZKPoK for plaintext equality
#include "../utility/serialization.hpp"
#include <time.h>
//#define DEMO           // demo mode 
//#define DEBUG        // show debug information 


namespace SDPT_UTXO{

using Serialization::operator<<; 
using Serialization::operator>>; 

// define the structure of system parameters
struct PP
{    
    BigInt MAXIMUM_COINS; 
    size_t anonset_num; // the number of AnonSet,include the sender
    Bullet::PP bullet_part;
    Solvent4UTXO::PP pp_solvent;
    TwistedExponentialElGamal::PP enc_part;
    //ExponentialElGamal::PP enc_part;
    //Pedersen::PP com_part;
    ECPoint pka; // supervisor's pk
};

// define the structure of system parameters
struct SP
{
    BigInt ska;   // supervisor's sk
};
// we reuse the account to name the UTXO output
struct Account 
{
    std::string identity;     // identity
    ECPoint pk;              // public key
    BigInt sk;              // secret key
    TwistedExponentialElGamal::CT coin_ct;  // current balance
    BigInt m;               // dangerous (should only be used for speeding up the proof generation)
    BigInt r;               
};

struct AnonSet
{
    std::string identity;
    ECPoint pk;
    TwistedExponentialElGamal::CT coin_tx; // current balance
};

struct Coin
{
    ECPoint pk;
    TwistedExponentialElGamal::CT coin_tx; // current balance
};

struct SupervisionResult
{
    std::vector<BigInt>cipher_supervison_value;
    std::vector<ECPoint> cipher_supervision_pk_sender;
    std::vector<size_t> cipher_supervision_index_sender;
};

//the structure of Anonymous Transaction 
struct AnonTransaction
{
   size_t num_input; // the number of input
   size_t num_output; // the number of output
   std::vector<Coin> input; // the input
   std::vector<Coin> output; // the pk of output

   BigInt epnumber; // the number of epoch

   //std::vector<std::string> identity; // the identity of participants;
   //validity proof
   Solvent4UTXO::Proof proof_any_out_of_many_proof; // NIZKPoK for any out of many proof
    
   Bullet::Proof proof_bullet_proof; // NIZKPoK for bullet proof

   std::vector<PlaintextKnowledge::Proof> proof_plaintext_knowledge_proof; // NIZKPoK for the Plaintext Knowledge

   // we will combine the proof_plaintext_knowledge_proof to  proof_plaintext_bit_equality_proof later

   std::vector<TwistedExponentialElGamal::CT> cipher_supervison_value;
   TwistedExponentialElGamal::CT cipher_supervision_sender;
   std::vector<PlaintextEquality4Two::Proof> proof_cipher_supervision_value;
   //Superviseable proof
   PlaintextKnowledge::Proof proof_cipher_supervision_sender; // NIZKPoK for the Plaintext Bit Equality
   
   //only num_input = 64, this wile be used 
   TwistedExponentialElGamal::CT cipher_supervision_sender_low;
   TwistedExponentialElGamal::CT cipher_supervision_sender_high;
   

};


std::string GetAnonTxFileName(AnonTransaction &anon_transaction)
{
    std::string tx_file = "Anonytx_way_" + anon_transaction.epnumber.ToHexString() + ".tx";    
    return tx_file; 
}


void PrintPP(PP &pp)
{
    // PrintSplitLine('-');
    // std::cout << "pp content >>>>>>" << std::endl; 
    // std::cout << "anonset_num = " << pp.anonset_num << std::endl; 
    // pp.pka.Print("supervisor's pk");  
    PrintSplitLine('-'); 
}

void PrintAccount(Account &Acct)
{
    // std::cout << Acct.identity << " account information >>> " << std::endl;     
    // Acct.pk.Print("pk"); 
    // std::cout << "encrypted balance:" << std::endl; 
    // TwistedExponentialElGamal::PrintCT(Acct.coin_ct);  // current balance
    // Acct.m.PrintInDec("m"); 
    PrintSplitLine('-'); 
}

void PrintAnonyTX(AnonTransaction &anon_transaction)
{
    

}


void SaveSP(SP &sp, std::string SDPT_SP_File)
{
    std::ofstream fout;
    fout.open(SDPT_SP_File, std::ios::binary); 
    fout << sp.ska;
    fout.close();   
}

void FetchSP(SP &sp, std::string SDPT_SP_File)
{
    std::ifstream fin; 
    fin.open(SDPT_SP_File, std::ios::binary); 
    fin >> sp.ska; 
    fin.close();   
}

void SavePP(PP &pp, std::string SDPT_PP_File)
{
    std::ofstream fout; 
    fout.open(SDPT_PP_File, std::ios::binary); 

    fout << pp.MAXIMUM_COINS; 
    fout << pp.anonset_num;
    fout << pp.pka; 

    fout << pp.bullet_part; 
    fout << pp.enc_part; 
    fout << pp.pp_solvent;


    fout.close();   
}

void FetchPP(PP &pp, std::string SDPT_PP_File)
{
    std::ifstream fin; 
    fin.open(SDPT_PP_File, std::ios::binary); 

    fin >> pp.MAXIMUM_COINS;  
    fin >> pp.anonset_num;
    fin >> pp.pka; 
 
    fin >> pp.bullet_part;
    fin >> pp.enc_part; 
    fin >> pp.pp_solvent;


    fin.close();   
}

void SaveAccount(Account &user, std::string sdp_account_file)
{
    std::ofstream fout; 
    fout.open(sdp_account_file, std::ios::binary);
    fout << user.identity;  
    fout << user.pk;              
    fout << user.sk;   
    fout << user.coin_ct;  
    fout << user.m; 
    fout << user.r;
    fout.close();  
}

void FetchAccount(Account &user, std::string sdp_account_file)
{
    std::ifstream fin; 
    fin.open(sdp_account_file, std::ios::binary);
    fin >> user.identity; 
    fin >> user.pk;              
    fin >> user.sk;             
    fin >> user.coin_ct;
    fin >> user.m; 
    fin >> user.r;
    fin.close();  
}

void SaveAnonyTx(AnonTransaction anon_transaction, std::string sdpt_anontx_file)
{
    std::ofstream fout; 
    std::ifstream fin; 
    fout.open(sdpt_anontx_file, std::ios::binary); 
    size_t num_input = anon_transaction.num_input;
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        fout << anon_transaction.input[i].pk;
        fout << anon_transaction.input[i].coin_tx;
    }
    size_t num_output = anon_transaction.num_output;
    for(auto i = 0; i < anon_transaction.num_output; i++)
    {
        fout << anon_transaction.output[i].pk;
        fout << anon_transaction.output[i].coin_tx;
    }

    fout << anon_transaction.proof_any_out_of_many_proof;
    fout << anon_transaction.proof_bullet_proof;
    fout << anon_transaction.proof_plaintext_knowledge_proof;

    fout.close();
    fin.open(sdpt_anontx_file, std::ios::ate | std::ios::binary);
    auto size_1 = fin.tellg();
    std::cout << sdpt_anontx_file << " size = " << size_1 << " bytes" << std::endl;
    fin.close();

    fout.open(sdpt_anontx_file, std::ios::binary | std::ios::app);
    fout << anon_transaction.cipher_supervison_value;
    fout << anon_transaction.cipher_supervision_sender;
    fout << anon_transaction.proof_cipher_supervision_sender;

    if(num_input == 64)
    {
        fout << anon_transaction.cipher_supervision_sender_low;
        fout << anon_transaction.cipher_supervision_sender_high;
    }

    fout.close();

    // calculate the size of tx_file
    // std::ifstream fin; 
    fin.open(sdpt_anontx_file, std::ios::ate | std::ios::binary);
    auto size_2 = fin.tellg();
    std::cout << sdpt_anontx_file << " size = " << size_2 << " bytes" << std::endl;
    fin.close(); 
    auto diff = size_2 - size_1;
    std::cout << "rate of the size of the file = " << double(diff)/double(size_2) << std::endl;
    return;
}


void FetchAnonyTx(AnonTransaction &anon_transaction, std::string sdpt_anontx_file)
{
    // Deserialize_AnonyTx(anon_transaction, tx_file); 
    std::ifstream fin; 
    fin.open(sdpt_anontx_file);
    size_t num_input = anon_transaction.num_input;
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        fin >> anon_transaction.input[i].pk;
        fin >> anon_transaction.input[i].coin_tx;
    }
    size_t num_output = anon_transaction.num_output;

    for(auto i = 0; i < anon_transaction.num_output; i++)
    {
        fin >> anon_transaction.output[i].pk;
        fin >> anon_transaction.output[i].coin_tx;
    }

    fin >> anon_transaction.proof_any_out_of_many_proof;
    fin >> anon_transaction.proof_bullet_proof;
    fin >> anon_transaction.proof_plaintext_knowledge_proof;
    fin >> anon_transaction.cipher_supervison_value;
    fin >> anon_transaction.cipher_supervision_sender;
    fin >> anon_transaction.proof_cipher_supervision_sender;

    if(num_input == 64)
    {
        fin >> anon_transaction.cipher_supervision_sender_low;
        fin >> anon_transaction.cipher_supervision_sender_high;
    }

    fin.close(); 
}


/* This function implements Setup algorithm of SDPT */
std::tuple<PP, SP> Setup(size_t LOG_MAXIMUM_COINS, size_t anonset_num, size_t num_receiver)
{
    PP pp; 
    SP sp; 

    if(IsPowerOfTwo(anonset_num) == false)
    { 
        std::cout << "parameters warning: (anonset_num) had better be a power of 2" << std::endl;
    }  
    pp.MAXIMUM_COINS = BigInt(uint64_t(pow(2, LOG_MAXIMUM_COINS)));  
    pp.anonset_num = anonset_num;
    size_t MAX_AGG_NUM = num_receiver ;
    size_t Log_anonset_num = size_t(log2(anonset_num-1)+1);
    // std::cout << "MAX_AGG_NUM = " << MAX_AGG_NUM << std::endl;
    // std::cout << "Log_anonset_num = " << Log_anonset_num << std::endl;
    pp.bullet_part = Bullet::Setup(LOG_MAXIMUM_COINS, MAX_AGG_NUM); 
    
    size_t TRADEOFF_NUM = 7; 
    pp.enc_part = TwistedExponentialElGamal::Setup(LOG_MAXIMUM_COINS, TRADEOFF_NUM);  
    pp.pp_solvent = Solvent4UTXO::Setup(anonset_num, pp.enc_part.g, pp.enc_part.h);
    
    //pp.com_part = Pedersen::Setup(4*Log_anonset_num+2); // the size of the Pedersen commitment is 4*Log_anonset_num+2

    std::tie(pp.pka, sp.ska) = TwistedExponentialElGamal::KeyGen(pp.enc_part);

    return {pp, sp};
}

/* initialize the encryption part for faster decryption */
void Initialize(PP &pp)
{
    std::cout << "initialize SDPT >>>" << std::endl;  
    TwistedExponentialElGamal::Initialize(pp.enc_part); 
    PrintSplitLine('-'); 
}

Coin Mint(PP &pp, BigInt &v, std::string identity, ECPoint &pk)
{
    Coin coin;
    BigInt r = GenRandomBigIntLessThan(order);
    coin.coin_tx = TwistedExponentialElGamal::Enc(pp.enc_part, coin.pk, v, r); 
    return coin; 
}
/* create an account for input identity */
Account CreateAccount(PP &pp, std::string identity, BigInt &init_balance)
{
    Account new_acct;
    new_acct.identity = identity;
    std::tie(new_acct.pk, new_acct.sk) = TwistedExponentialElGamal::KeyGen(pp.enc_part); // generate a keypair
    new_acct.m = init_balance; 

    // initialize account balance with 0 coins
    BigInt r = GenRandomBigIntLessThan(order);
    new_acct.r = r;
    new_acct.coin_ct = TwistedExponentialElGamal::Enc(pp.enc_part, new_acct.pk, init_balance, r);

    #ifdef DEMO
        std::cout << identity << "'s SDPT account creation succeeds" << std::endl;
        new_acct.pk.Print("pk"); 
        std::cout << identity << "'s initial balance = "; 
        new_acct.m.PrintInDec(); 
        std::cout << std::endl;
        PrintSplitLine('-'); 
    #endif 

    return new_acct;
}

/* reveal the balance */ 
BigInt RevealBalance(PP &pp, Account &Acct)
{
    return TwistedExponentialElGamal::Dec(pp.enc_part, Acct.sk, Acct.coin_ct); 
}

// generate a random number(not really random) from 0 to n-1 (n is the number of AnonSet)
size_t getranindex(size_t n)
{
    srand(time(0));
    return rand() % n;
}

// create a anonymous transaction: pk1 transfers v coins to pk2
AnonTransaction CreateAnonTransaction(PP &pp, std::vector<Account> &Acct_sender, std::vector<BigInt> &v, std::vector<ECPoint> pk_receiver, 
    std::vector<Coin> &coin_input, std::vector<BigInt> sk_sender, BigInt epnumber)
{
    AnonTransaction anon_transaction;
    anon_transaction.epnumber = epnumber;
    anon_transaction.num_input = coin_input.size();

    if(pk_receiver.size() != v.size())
    {
        std::cout << "error: the number of receivers is not equal to the number of coins" << std::endl;
        return anon_transaction;
    }
    anon_transaction.num_output = pk_receiver.size();
    anon_transaction.epnumber = epnumber;
    // initialize the input
    anon_transaction.input = coin_input;
    // initialize the output
    std::vector<BigInt> vec_r_coin_output(pk_receiver.size());
    Bullet::PP pp_bullet = pp.bullet_part;
    Bullet::Instance bullet_instance ;
    Bullet::Witness bullet_witness ;
    Bullet::Proof proof_bullet_proof;
    PlaintextKnowledge::PP pp_plaintext_knowledge = PlaintextKnowledge::Setup(pp.enc_part);
    PlaintextKnowledge::Instance plaintext_knowledge_instance;
    PlaintextKnowledge::Witness plaintext_knowledge_witness;
    PlaintextKnowledge::Proof plaintext_knowledge_proof;

    auto start_time = std::chrono::steady_clock::now();

    std::string transcript_str_Plaintext = "";
    for(auto i = 0; i < pk_receiver.size(); i++)
    {
        Coin coin;
        coin.pk = pk_receiver[i];
        vec_r_coin_output[i] = GenRandomBigIntLessThan(order);
        coin.coin_tx = TwistedExponentialElGamal::Enc(pp.enc_part, coin.pk, v[i], vec_r_coin_output[i]);
        //generate the bulletproof
        bullet_instance.C.push_back(coin.coin_tx.Y);
        bullet_witness.r.push_back(vec_r_coin_output[i]);
        bullet_witness.v.push_back(v[i]);
        anon_transaction.output.push_back(coin);
        //generate the plaintext knowledge proof
        transcript_str_Plaintext = "";
        plaintext_knowledge_instance.pk = coin.pk;
        plaintext_knowledge_instance.ct = coin.coin_tx;
        plaintext_knowledge_witness.r = vec_r_coin_output[i];
        plaintext_knowledge_witness.v = v[i];
        plaintext_knowledge_proof = PlaintextKnowledge::Prove(pp_plaintext_knowledge, plaintext_knowledge_instance, plaintext_knowledge_witness, transcript_str_Plaintext );
        anon_transaction.proof_plaintext_knowledge_proof.push_back(plaintext_knowledge_proof);  
    }
    //std::cout << "output.size" << anon_transaction.output.size() << std::endl;
    std::string transcript_str = "";
    Bullet::Prove(pp_bullet, bullet_instance, bullet_witness, transcript_str, proof_bullet_proof);
    anon_transaction.proof_bullet_proof = proof_bullet_proof;
    // std::cout << "bulletproof generation finishes" << std::endl;
    // generate the PlaintextEquality4Two proof
    std::vector<TwistedExponentialElGamal::CT> cipher_supervison_value(pk_receiver.size());
    TwistedExponentialElGamal::CT cipher_supervision_sender;
    std::vector<BigInt> vec_r_supervision_value(pk_receiver.size());
    
    for(auto i = 0 ; i < pk_receiver.size();i++)
    {
        vec_r_supervision_value[i] = GenRandomBigIntLessThan(order);
        cipher_supervison_value[i] = TwistedExponentialElGamal::Enc(pp.enc_part, pp.pka, v[i], vec_r_supervision_value[i]);
        anon_transaction.cipher_supervison_value.push_back(cipher_supervison_value[i]);
    }
    PlaintextEquality4Two::PP pp_plaintext_equality = PlaintextEquality4Two::Setup(pp.enc_part);
    PlaintextEquality4Two::Instance plaintext_equality_instance;
    PlaintextEquality4Two::Witness plaintext_equality_witness;
    PlaintextEquality4Two::Proof plaintext_equality_proof;
    std::string transcript_str_Plaintext_equality = "";
    for(auto i =0 ; i< pk_receiver.size(); i++)
    {
        transcript_str_Plaintext_equality = "";
        plaintext_equality_instance.pk1 = pk_receiver[i];
        plaintext_equality_instance.pk2 = pp.pka;
        plaintext_equality_instance.ct1 = anon_transaction.output[i].coin_tx;
        plaintext_equality_instance.ct2 = cipher_supervison_value[i];
        plaintext_equality_witness.v = v[i];
        plaintext_equality_witness.r1 = vec_r_coin_output[i];
        plaintext_equality_witness.r2 = vec_r_supervision_value[i];
        plaintext_equality_proof = PlaintextEquality4Two::Prove(pp_plaintext_equality, plaintext_equality_instance, plaintext_equality_witness, transcript_str_Plaintext_equality);
        anon_transaction.proof_cipher_supervision_value.push_back(plaintext_equality_proof);
    }

    //generate the any out of many proof
    Solvent4UTXO::PP pp_any_out_of_many = pp.pp_solvent;
    Solvent4UTXO::Instance solvent_instance;
    solvent_instance.vec_com.resize(anon_transaction.num_input);
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        solvent_instance.vec_com[i] = anon_transaction.input[i].pk;
    }
    solvent_instance.CoinInput.resize(anon_transaction.num_input);
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        solvent_instance.CoinInput[i] = anon_transaction.input[i].coin_tx.Y;
        //anon_transaction.input[i].coin_tx.Y.Print("anon_transaction.input[i].coin_tx.Y");
    }
    solvent_instance.CoinOutput.resize(anon_transaction.num_output);
    for(auto i = 0; i < anon_transaction.num_output; i++)
    {
        solvent_instance.CoinOutput[i] = anon_transaction.output[i].coin_tx.Y;
        //anon_transaction.output[i].coin_tx.Y.Print("anon_transaction.output[i].coin_tx.Y");
    }
    Solvent4UTXO::Witness solvent_witness;
    solvent_witness.vec_s = sk_sender;
    for(auto i = 0; i < solvent_witness.vec_s.size(); i++)
    {
        solvent_witness.vec_s[i].Print("solvent_witness.vec_s[i]");
    }
    solvent_witness.vec_r_coin_output = vec_r_coin_output;
    solvent_witness.vec_r_coin_input.resize(Acct_sender.size());
    //compute bit vector
    std::vector<BigInt> vec_b(anon_transaction.num_input);
    size_t index_j = 0;
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        if(index_j >= Acct_sender.size())
        {
            vec_b[i] = bn_0;
        }
        else
        {
            if(anon_transaction.input[i].pk == Acct_sender[index_j].pk)
            {
                vec_b[i] = bn_1;
                index_j++;
            }
            else
            {
                vec_b[i] = bn_0;
            }
        }
    }
    solvent_witness.vec_b = vec_b;
    /*size_t index2bn =0;
    //need to fix later
    auto b_size = vec_b.size()-1;
    for(auto i = b_size; i>0; i--)
    {
        //std::cout << "ii[i] = " << i << std::endl;
        if(vec_b[i] == bn_1)
        {
            index2bn = index2bn + pow(2, i);
        }  
    }
    if(vec_b[0] == bn_1)
    {
        index2bn = index2bn + 1;
    }*/
    //BigInt super_senderindex2bn = BigInt(index2bn);
    BigInt super_senderindex2bn = FromBitVector(vec_b);

    BigInt cipher_supervision_sender_r = GenRandomBigIntLessThan(order);
    cipher_supervision_sender = TwistedExponentialElGamal::Enc(pp.enc_part, pp.pka, super_senderindex2bn, cipher_supervision_sender_r);
    anon_transaction.cipher_supervision_sender = cipher_supervision_sender;
    solvent_instance.Com = cipher_supervision_sender.Y;

    if(anon_transaction.num_input == 64)
    {
        std::vector<BigInt> vec_b_low(32);
        std::vector<BigInt> vec_b_high(32);
        std::copy(vec_b.begin(), vec_b.begin()+32, vec_b_low.begin());
        std::copy(vec_b.begin()+32, vec_b.end(), vec_b_high.begin());
        BigInt super_senderindex2bn_low = FromBitVector(vec_b_low);
        BigInt super_senderindex2bn_high = FromBitVector(vec_b_high);
        TwistedExponentialElGamal::CT cipher_supervision_sender_low = TwistedExponentialElGamal::Enc(pp.enc_part, pp.pka, super_senderindex2bn_low, cipher_supervision_sender_r);
        TwistedExponentialElGamal::CT cipher_supervision_sender_high = TwistedExponentialElGamal::Enc(pp.enc_part, pp.pka, super_senderindex2bn_high, cipher_supervision_sender_r);
        anon_transaction.cipher_supervision_sender_low = cipher_supervision_sender_low;
        anon_transaction.cipher_supervision_sender_high = cipher_supervision_sender_high;
       
    }

    //PrintBigIntVector(solvent_witness.vec_b, "solvent_witness.vec_b");
    for(auto i = 0; i < Acct_sender.size(); i++)
    {
        solvent_witness.vec_r_coin_input[i] = Acct_sender[i].r;
    }
    solvent_witness.v = super_senderindex2bn;
    solvent_witness.r = cipher_supervision_sender_r;
    Solvent4UTXO::Proof proof_any_out_of_many_proof;
    std::string transcript_str_any_out_of_many = "";
    Solvent4UTXO::Prove(pp_any_out_of_many, solvent_instance, solvent_witness, proof_any_out_of_many_proof, transcript_str_any_out_of_many);
    anon_transaction.proof_any_out_of_many_proof = proof_any_out_of_many_proof;

    //generate the plaintext knowledge proof of the supervision index
    PlaintextKnowledge::PP pp_plaintext_knowledge_supervision = PlaintextKnowledge::Setup(pp.enc_part);
    auto start_time_audit = std::chrono::steady_clock::now();
    PlaintextKnowledge::Instance plaintext_knowledge_instance_supervision;
    PlaintextKnowledge::Witness plaintext_knowledge_witness_supervision;
    PlaintextKnowledge::Proof plaintext_knowledge_proof_supervision;
    std::string transcript_str_Plaintext_supervision = "";
    plaintext_knowledge_instance_supervision.pk = pp.pka;
    plaintext_knowledge_instance_supervision.ct = cipher_supervision_sender;
    plaintext_knowledge_witness_supervision.v = super_senderindex2bn;
    plaintext_knowledge_witness_supervision.r = cipher_supervision_sender_r;
    plaintext_knowledge_proof_supervision = PlaintextKnowledge::Prove(pp_plaintext_knowledge_supervision, plaintext_knowledge_instance_supervision, plaintext_knowledge_witness_supervision, transcript_str_Plaintext_supervision);
    anon_transaction.proof_cipher_supervision_sender = plaintext_knowledge_proof_supervision;
    auto end_time_audit = std::chrono::steady_clock::now();
    auto time_diff_audit = end_time_audit - start_time_audit;
    std::cout << "audit time = " << std::chrono::duration<double, std::milli>(time_diff_audit).count() << " ms" << std::endl;

    auto end_time = std::chrono::steady_clock::now();
    auto time_diff = end_time - start_time;
    std::cout << "transaction generation time = " << std::chrono::duration<double, std::milli>(time_diff).count() << " ms" << std::endl;

    std::cout << "rate of generation time = " << std::chrono::duration<double,std::milli>(time_diff_audit).count()/std::chrono::duration<double, std::milli>(time_diff).count() << " ms" << std::endl;
    return anon_transaction;
}   


bool VerifyAnoyTX(PP &pp, AnonTransaction anon_transaction)
{
    // verify the bulletproof
    auto start_time = std::chrono::steady_clock::now();
    bool condition1 = false;
    Bullet::PP pp_bullet = pp.bullet_part;
    Bullet::Instance bullet_instance ;
    Bullet::Proof proof_bullet_proof = anon_transaction.proof_bullet_proof;
    for(auto i = 0; i < anon_transaction.num_output; i++)
    {
        bullet_instance.C.push_back(anon_transaction.output[i].coin_tx.Y);
    }
    std::string transcript_str = "";
    condition1 = Bullet::Verify(pp_bullet, bullet_instance, transcript_str, proof_bullet_proof);
    if(condition1 == false)
    {
        std::cout << "bulletproof verification fails" << std::endl;
    }
    // verify the PlaintextEquality4Two proof
    PlaintextEquality4Two::PP pp_plaintext_equality = PlaintextEquality4Two::Setup(pp.enc_part);
    PlaintextEquality4Two::Instance plaintext_equality_instance;
    PlaintextEquality4Two::Proof plaintext_equality_proof;
    std::string transcript_str_Plaintext_equality = "";
    for(auto i =0 ; i< anon_transaction.num_output; i++)
    {
        transcript_str_Plaintext_equality = "";
        plaintext_equality_instance.pk1 = anon_transaction.output[i].pk;
        plaintext_equality_instance.pk2 = pp.pka;
        plaintext_equality_instance.ct1 = anon_transaction.output[i].coin_tx;
        plaintext_equality_instance.ct2 = anon_transaction.cipher_supervison_value[i];
        bool condition = PlaintextEquality4Two::Verify(pp_plaintext_equality, plaintext_equality_instance, transcript_str_Plaintext_equality, anon_transaction.proof_cipher_supervision_value[i]);
        if(condition == false)
        {
            std::cout << "plaintext equality proof verification fails" << std::endl;
        }
    }

    // verify the any out of many proof
    Solvent4UTXO::PP pp_any_out_of_many = pp.pp_solvent;
    Solvent4UTXO::Instance solvent_instance;
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        solvent_instance.vec_com.push_back(anon_transaction.input[i].pk);
        //anon_transaction.input[i].pk.Print("anon_transaction.input[i].pk");
    }
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        solvent_instance.CoinInput.push_back(anon_transaction.input[i].coin_tx.Y);
    }
    for(auto i = 0; i < anon_transaction.num_output; i++)
    {
        solvent_instance.CoinOutput.push_back(anon_transaction.output[i].coin_tx.Y);
    }
    solvent_instance.Com = anon_transaction.cipher_supervision_sender.Y;
    // verify the supervision index proof
    PlaintextKnowledge::PP pp_plaintext_knowledge_supervision = PlaintextKnowledge::Setup(pp.enc_part);
    auto start_time_audit = std::chrono::steady_clock::now();
    std::string transcript_str_Plaintext_supervision = "";
    PlaintextKnowledge::Instance plaintext_knowledge_instance_supervision;
    plaintext_knowledge_instance_supervision.pk = pp.pka;
    plaintext_knowledge_instance_supervision.ct = anon_transaction.cipher_supervision_sender;
    PlaintextKnowledge::Proof plaintext_knowledge_proof_supervision = anon_transaction.proof_cipher_supervision_sender;
    bool condition3 = PlaintextKnowledge::Verify(pp_plaintext_knowledge_supervision, plaintext_knowledge_instance_supervision, transcript_str_Plaintext_supervision, plaintext_knowledge_proof_supervision);
    auto end_time_audit = std::chrono::steady_clock::now();
    auto time_diff_audit = end_time_audit - start_time_audit;
    std::cout << "audit time = " << std::chrono::duration<double, std::milli>(time_diff_audit).count() << " ms" << std::endl;

    if(condition3 == false)
    {
        std::cout << "plaintext knowledge proof of supervision index verification fails" << std::endl;
    }
    //verify the PlaintextKnowledge proof
    PlaintextKnowledge::PP pp_plaintext_knowledge = PlaintextKnowledge::Setup(pp.enc_part);
    std::string transcript_str_Plaintext = "";
    for(auto i = 0; i < anon_transaction.num_output; i++)
    {
        transcript_str_Plaintext = "";
        PlaintextKnowledge::Instance plaintext_knowledge_instance;
        plaintext_knowledge_instance.pk = anon_transaction.output[i].pk;
        plaintext_knowledge_instance.ct = anon_transaction.output[i].coin_tx;
        PlaintextKnowledge::Proof plaintext_knowledge_proof = anon_transaction.proof_plaintext_knowledge_proof[i];
        bool condition = PlaintextKnowledge::Verify(pp_plaintext_knowledge, plaintext_knowledge_instance, transcript_str_Plaintext, plaintext_knowledge_proof);
        if(condition == false)
        {
            std::cout << "plaintext knowledge proof verification fails" << std::endl;
        }
    }
    Solvent4UTXO::Proof proof_any_out_of_many_proof = anon_transaction.proof_any_out_of_many_proof;
    std::string transcript_str_any_out_of_many = "";
    bool condition2 = Solvent4UTXO::Verify(pp_any_out_of_many, solvent_instance, proof_any_out_of_many_proof, transcript_str_any_out_of_many);
    auto end_time = std::chrono::steady_clock::now();
    auto time_diff = end_time - start_time;
    std::cout << "verification time = " << std::chrono::duration<double, std::milli>(time_diff).count() << " ms" << std::endl;
    std::cout << "rate of verification time = " << std::chrono::duration<double,std::milli>(time_diff_audit).count()/std::chrono::duration<double, std::milli>(time_diff).count() << " ms" << std::endl;
    if(condition2 == false)
    {
        std::cout << "any out of many proof verification fails" << std::endl;
    }
    return condition1 && condition2;
    
}


std::string ExtractToSignMessageFromAnoyTx(AnonTransaction anon_transaction)
{
    std::string str;
   
    return str;
}

// void UpdateAccount(PP &pp, AnonTransaction &anon_transaction, std::vector<Account> accountlist_miner)
// {     
//     // update the balance
//     // std::cout << "update accounts >>>" << std::endl;
//     // for(auto i = 0; i < anon_transaction.number; i++)
//     // {
//     //     accountlist_miner[i].balance_ct = anon_transaction.balance_tx[i];
//     //     accountlist_miner[i].m = ExponentialElGamal::Dec(pp.enc_part, accountlist_miner[i].sk, accountlist_miner[i].balance_ct);
//     //     SaveAccount(accountlist_miner[i], accountlist_miner[i].identity + ".account");
//     // }
      
// } 


/* check if a anonymous tx is valid and update accounts if yes */
//we use a dirty way to realize the function,miner should not have the account.sk
bool Miner(PP &pp,AnonTransaction anon_transaction)
{
    std::string tx_file = GetAnonTxFileName(anon_transaction); 
    
    if(VerifyAnoyTX(pp, anon_transaction) == true){
        SaveAnonyTx(anon_transaction, tx_file);  //need to realize
        //std::cout << tx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        //std::cout << tx_file << " is discarded" << std::endl; 
        return false; 
    }

}
std::vector<size_t> Decompose(size_t l, size_t n, size_t m)
{
    std::vector<size_t> vec_index(m); 
    for(auto j = 0; j < m; j++){
        vec_index[j] = l % n;  
        l = l / n; 
    }
    return vec_index;  
}
/* supervisor opens CTx */
SupervisionResult SuperviseAnonTx(SP &sp, PP &pp, AnonTransaction &anon_transaction)
{
    SupervisionResult result;
    std::cout << "Supervise " << GetAnonTxFileName(anon_transaction) << std::endl;
    auto start_time = std::chrono::steady_clock::now();
    size_t num_output = anon_transaction.num_output;
    for(auto i = 0; i < num_output; i++)
    {
        BigInt v = TwistedExponentialElGamal::Dec(pp.enc_part, sp.ska, anon_transaction.cipher_supervison_value[i]);
        result.cipher_supervison_value.push_back(v);
        result.cipher_supervision_pk_sender.push_back(anon_transaction.output[i].pk);
        //std::cout << "sender pay " << BN_bn2dec(v.bn_ptr) << " coins to receiver: " <<anon_transaction.output[i].pk.ToHexString() << std::endl;
        //PrintSplitLine('-');
    }
    if(anon_transaction.num_input == 64)
    {
        BigInt v_low = TwistedExponentialElGamal::Dec(pp.enc_part, sp.ska, anon_transaction.cipher_supervision_sender_low);
        BigInt v_high = TwistedExponentialElGamal::Dec(pp.enc_part, sp.ska, anon_transaction.cipher_supervision_sender_high);
        size_t index_low = v_low.ToUint64();
        size_t index_high = v_high.ToUint64();
        std::vector<size_t> vec_index_low = Decompose(index_low,2, pp.anonset_num/2);
        std::vector<size_t> vec_index_high = Decompose(index_high,2, pp.anonset_num/2);
        std::vector<size_t> vec_index;
        vec_index.insert(vec_index.end(), vec_index_low.begin(), vec_index_low.end());
        vec_index.insert(vec_index.end(), vec_index_high.begin(), vec_index_high.end());
        for(auto i = 0; i < vec_index.size(); i++)
        {
            std::cout << "vec_index[" << i << "] = " << vec_index[i] << std::endl;
        }
    }
    else
    {
        BigInt index = TwistedExponentialElGamal::Dec(pp.enc_part, sp.ska, anon_transaction.cipher_supervision_sender);
        //std::cout << "the sender's index is " << BN_bn2dec(index.bn_ptr) << std::endl;
        size_t index2 = index.ToUint64();
        //std::cout << "the sender's index is " << index2 << std::endl;
        std::vector<size_t> vec_index = Decompose(index2,2, pp.anonset_num);
    }
    
    // for(auto i = 0; i < vec_index.size(); i++)
    // {
    //     std::cout << "vec_index[" << i << "] = " << vec_index[i] << std::endl;
    // }
    auto end_time = std::chrono::steady_clock::now();
    auto time_diff = end_time - start_time;
    std::cout << "supervision time = " << std::chrono::duration<double, std::milli>(time_diff).count() << " ms" << std::endl;


    return result;
}

}
#endif
