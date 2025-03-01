/****************************************************************************
this hpp implements the SDPT functionality 
*****************************************************************************/
#ifndef SDPT_UTXO_HPP_
#define SDPT_UTXO_HPP_

#include "../pke/twisted_exponential_elgamal.hpp"        // implement twisted ElGamal PKE
#include "../zkp/bulletproofs/bullet_proof.hpp"          // implement Bulletproof
#include "../zkp/nizk/nizk_solvent_any_out_of_many.hpp" // implement any out of many proof
#include "../zkp/nizk/nizk_plaintext_bit_equality.hpp" // NIZKPoK for plaintext bit equality
#include "../zkp/nizk/nizk_multi_plaintext_equality.hpp" // NIZKPoK for multi plaintext equality
#include "../utility/serialization.hpp"
#include <time.h>
#define DEMO           // demo mode 
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

//the structure of Anonymous Transaction 1
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

   
   std::vector<TwistedExponentialElGamal::CT> cipher_supervison_value;
   TwistedExponentialElGamal::CT cipher_supervision_sender;
   //Superviseable proof
   //PlaintextBitEquality::Proof proof_plaintext_bit_equality_proof; // NIZKPoK for the Plaintext Bit Equality

};


std::string GetAnonTxFileName(AnonTransaction &anon_transaction)
{
    std::string tx_file = "Anonytx_way_" + anon_transaction.epnumber.ToHexString() + ".tx";    
    return tx_file; 
}


void PrintPP(PP &pp)
{
    PrintSplitLine('-');
    std::cout << "pp content >>>>>>" << std::endl; 
    std::cout << "anonset_num = " << pp.anonset_num << std::endl; 
    pp.pka.Print("supervisor's pk");  
    PrintSplitLine('-'); 
}

void PrintAccount(Account &Acct)
{
    std::cout << Acct.identity << " account information >>> " << std::endl;     
    Acct.pk.Print("pk"); 
    std::cout << "encrypted balance:" << std::endl; 
    TwistedExponentialElGamal::PrintCT(Acct.coin_ct);  // current balance
    Acct.m.PrintInDec("m"); 
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
    fout << anon_transaction.cipher_supervison_value;
    fout << anon_transaction.cipher_supervision_sender;
    
    fout.close();

    // calculate the size of tx_file
    std::ifstream fin; 
    fin.open(sdpt_anontx_file, std::ios::ate | std::ios::binary);
    std::cout << sdpt_anontx_file << " size = " << fin.tellg() << " bytes" << std::endl;
    fin.close(); 
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
    fin >> anon_transaction.cipher_supervison_value;
    fin >> anon_transaction.cipher_supervision_sender;

    fin.close(); 
}


/* This function implements Setup algorithm of SDPT */
std::tuple<PP, SP> Setup(size_t LOG_MAXIMUM_COINS, size_t anonset_num)
{
    PP pp; 
    SP sp; 

    if(IsPowerOfTwo(anonset_num) == false)
    { 
        std::cout << "parameters warning: (anonset_num) had better be a power of 2" << std::endl;
    }  
    pp.MAXIMUM_COINS = BigInt(uint64_t(pow(2, LOG_MAXIMUM_COINS)));  
    pp.anonset_num = anonset_num;
    size_t MAX_AGG_NUM = anonset_num ;
    size_t Log_anonset_num = size_t(log2(anonset_num-1)+1);
    std::cout << "MAX_AGG_NUM = " << MAX_AGG_NUM << std::endl;
    std::cout << "Log_anonset_num = " << Log_anonset_num << std::endl;
    pp.bullet_part = Bullet::Setup(LOG_MAXIMUM_COINS, MAX_AGG_NUM); 
    
    size_t TRADEOFF_NUM = 7; 
    pp.enc_part = TwistedExponentialElGamal::Setup(LOG_MAXIMUM_COINS, TRADEOFF_NUM);  
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
    }
    std::string transcript_str = "";
    Bullet::Prove(pp_bullet, bullet_instance, bullet_witness, transcript_str, proof_bullet_proof);
    anon_transaction.proof_bullet_proof = proof_bullet_proof;
    //generate the any out of many proof
    Solvent4UTXO::PP pp_any_out_of_many = Solvent4UTXO::Setup(anon_transaction.num_input, pp.enc_part.g, pp.enc_part.h);
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
    }
    solvent_instance.CoinOutput.resize(anon_transaction.num_output);
    for(auto i = 0; i < anon_transaction.num_output; i++)
    {
        solvent_instance.CoinOutput[i] = anon_transaction.output[i].coin_tx.Y;
    }
    Solvent4UTXO::Witness solvent_witness;
    solvent_witness.vec_s = sk_sender;
    solvent_witness.vec_r_coin_output = vec_r_coin_output;
    solvent_witness.vec_r_coin_input.resize(Acct_sender.size());
    for(auto i = 0; i < Acct_sender.size(); i++)
    {
        solvent_witness.vec_r_coin_input[i] = Acct_sender[i].r;
    }
    Solvent4UTXO::Proof proof_any_out_of_many_proof;
    std::string transcript_str_any_out_of_many = "";
    Solvent4UTXO::Prove(pp_any_out_of_many, solvent_instance, solvent_witness, proof_any_out_of_many_proof, transcript_str_any_out_of_many);
    anon_transaction.proof_any_out_of_many_proof = proof_any_out_of_many_proof;
    return anon_transaction;
}   


bool VerifyAnoyTX(PP &pp, AnonTransaction anon_transaction)
{
    // verify the bulletproof
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
        return false;
    }
    // verify the any out of many proof
    Solvent4UTXO::PP pp_any_out_of_many = Solvent4UTXO::Setup(anon_transaction.num_input, pp.enc_part.g, pp.enc_part.h);
    Solvent4UTXO::Instance solvent_instance;
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        solvent_instance.vec_com.push_back(anon_transaction.input[i].pk);
    }
    for(auto i = 0; i < anon_transaction.num_input; i++)
    {
        solvent_instance.CoinInput.push_back(anon_transaction.input[i].coin_tx.Y);
    }
    for(auto i = 0; i < anon_transaction.num_output; i++)
    {
        solvent_instance.CoinOutput.push_back(anon_transaction.output[i].coin_tx.Y);
    }
    Solvent4UTXO::Proof proof_any_out_of_many_proof = anon_transaction.proof_any_out_of_many_proof;
    std::string transcript_str_any_out_of_many = "";
    bool condition2 = Solvent4UTXO::Verify(pp_any_out_of_many, solvent_instance, proof_any_out_of_many_proof, transcript_str_any_out_of_many);
    if(condition2 == false)
    {
        std::cout << "any out of many proof verification fails" << std::endl;
        return false;
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
        std::cout << tx_file << " is recorded on the blockchain" << std::endl; 
        return true; 
    }
    else{
        std::cout << tx_file << " is discarded" << std::endl; 
        return false; 
    }

}


/* supervisor opens CTx */
SupervisionResult SuperviseAnonTx(SP &sp, PP &pp, AnonTransaction &anon_transaction)
{
    SupervisionResult result;
    return result;
}

}
#endif
