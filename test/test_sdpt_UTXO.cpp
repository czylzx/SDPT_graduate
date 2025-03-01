#include "../sdpt/sdpt_UTXO.hpp"
#include "../crypto/setup.hpp"
// count the number of transaction
BigInt count=bn_0;
void Build_SDPT_Test_Enviroment(size_t ringnumber)
{
    PrintSplitLine('-'); 
    std::cout << "build test enviroment for SDPT_UTXO >>>" << std::endl; 
    PrintSplitLine('-'); 
    std::cout << "setup SDPT_UTXO system" << std::endl; 
    // setup adcp system
    
    size_t LOG_MAXIMUM_COINS = 32;      

    size_t AnonySetSize = ringnumber;  

    SDPT_UTXO::SP sp;
    SDPT_UTXO::PP pp;

    std::tie(pp, sp) = SDPT_UTXO::Setup(LOG_MAXIMUM_COINS, AnonySetSize); 

    SDPT_UTXO::Initialize(pp);

    std::string SDPT_SP_Filename = "sdpt.sp"; 
    SDPT_UTXO::SaveSP(sp, SDPT_SP_Filename); 

    std::string sdpt_PP_Filename = "sdpt.pp"; 
    SDPT_UTXO::SavePP(pp, sdpt_PP_Filename); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");

    // create accounts for Alice and Bob and Tax
    std::cout << "generate 16 accounts" << std::endl; 
    PrintSplitLine('-'); 

    BigInt Alice_balance = BigInt(512); 
    SDPT_UTXO::Account Acct_Alice = SDPT_UTXO::CreateAccount(pp, "Alice", Alice_balance); 
    std::string Alice_Acct_FileName = "Alice.account"; 
    SDPT_UTXO::SaveAccount(Acct_Alice, Alice_Acct_FileName); 

    BigInt Bob_balance = BigInt(256);
    SDPT_UTXO::Account Acct_Bob = SDPT_UTXO::CreateAccount(pp, "Bob", Bob_balance); 
    std::string Bob_Acct_FileName = "Bob.account"; 
    SDPT_UTXO::SaveAccount(Acct_Bob, Bob_Acct_FileName); 

    BigInt Carl_balance = BigInt(128); 
    SDPT_UTXO::Account Acct_Carl = SDPT_UTXO::CreateAccount(pp, "Carl", Carl_balance); 
    std::string Carl_Acct_FileName = "Carl.account"; 
    SDPT_UTXO::SaveAccount(Acct_Carl, Carl_Acct_FileName); 

    BigInt David_balance = BigInt(64);
    SDPT_UTXO::Account Acct_David = SDPT_UTXO::CreateAccount(pp, "David", David_balance);
    std::string David_Acct_FileName = "David.account";
    SDPT_UTXO::SaveAccount(Acct_David, David_Acct_FileName);

    BigInt Eve_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Eve = SDPT_UTXO::CreateAccount(pp, "Eve", Eve_balance);
    std::string Eve_Acct_FileName = "Eve.account";
    SDPT_UTXO::SaveAccount(Acct_Eve, Eve_Acct_FileName);

    BigInt Frank_balance = BigInt(16);
    SDPT_UTXO::Account Acct_Frank = SDPT_UTXO::CreateAccount(pp, "Frank", Frank_balance);
    std::string Frank_Acct_FileName = "Frank.account";
    SDPT_UTXO::SaveAccount(Acct_Frank, Frank_Acct_FileName);

    BigInt Grace_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Grace = SDPT_UTXO::CreateAccount(pp, "Grace", Grace_balance);
    std::string Grace_Acct_FileName = "Grace.account";
    SDPT_UTXO::SaveAccount(Acct_Grace, Grace_Acct_FileName);

    BigInt Henry_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Henry = SDPT_UTXO::CreateAccount(pp, "Henry", Henry_balance);
    std::string Henry_Acct_FileName = "Henry.account";
    SDPT_UTXO::SaveAccount(Acct_Henry, Henry_Acct_FileName);

    BigInt Ida_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Ida = SDPT_UTXO::CreateAccount(pp, "Ida", Ida_balance);
    std::string Ida_Acct_FileName = "Ida.account";
    SDPT_UTXO::SaveAccount(Acct_Ida, Ida_Acct_FileName);

    BigInt Jack_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Jack = SDPT_UTXO::CreateAccount(pp, "Jack", Jack_balance);
    std::string Jack_Acct_FileName = "Jack.account";
    SDPT_UTXO::SaveAccount(Acct_Jack, Jack_Acct_FileName);

    BigInt Kate_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Kate = SDPT_UTXO::CreateAccount(pp, "Kate", Kate_balance);
    std::string Kate_Acct_FileName = "Kate.account";
    SDPT_UTXO::SaveAccount(Acct_Kate, Kate_Acct_FileName);

    BigInt Leo_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Leo = SDPT_UTXO::CreateAccount(pp, "Leo", Leo_balance);
    std::string Leo_Acct_FileName = "Leo.account";
    SDPT_UTXO::SaveAccount(Acct_Leo, Leo_Acct_FileName);

    BigInt Mary_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Mary = SDPT_UTXO::CreateAccount(pp, "Mary", Mary_balance);
    std::string Mary_Acct_FileName = "Mary.account";
    SDPT_UTXO::SaveAccount(Acct_Mary, Mary_Acct_FileName);

    BigInt Nick_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Nick = SDPT_UTXO::CreateAccount(pp, "Nick", Nick_balance);
    std::string Nick_Acct_FileName = "Nick.account";
    SDPT_UTXO::SaveAccount(Acct_Nick, Nick_Acct_FileName);

    BigInt Olivia_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Olivia = SDPT_UTXO::CreateAccount(pp, "Olivia", Olivia_balance);
    std::string Olivia_Acct_FileName = "Olivia.account";
    SDPT_UTXO::SaveAccount(Acct_Olivia, Olivia_Acct_FileName);

    BigInt Paul_balance = BigInt(32);
    SDPT_UTXO::Account Acct_Paul = SDPT_UTXO::CreateAccount(pp, "Paul", Paul_balance);
    std::string Paul_Acct_FileName = "Paul.account";
    SDPT_UTXO::SaveAccount(Acct_Paul, Paul_Acct_FileName);

    BigInt Tax_balance = bn_0; 
    SDPT_UTXO::Account Acct_Tax = SDPT_UTXO::CreateAccount(pp, "Tax", Tax_balance); 
    std::string Tax_Acct_FileName = "Tax.account"; 
    SDPT_UTXO::SaveAccount(Acct_Tax, Tax_Acct_FileName); 

    std::cout << "press any key to continue >>>" << std::endl; 
    system ("read");
} 

void Emulate_SDPT_System(size_t ringnumber, size_t num_sender, size_t num_receiver)
{
    size_t RANGE_LEN = 32; // set the range to be [0, 2^32-1]
    size_t AGG_NUM = 2; 
    
    SDPT_UTXO::SP sp;  
    SDPT_UTXO::FetchSP(sp, "sdpt.sp"); 

    SDPT_UTXO::PP pp;  
    SDPT_UTXO::FetchPP(pp, "sdpt.pp"); 
    SDPT_UTXO::PrintPP(pp); 

    SDPT_UTXO::Account Acct_Alice;  
    SDPT_UTXO::FetchAccount(Acct_Alice, "Alice.account"); 
    //SDPT_UTXO::PrintAccount(Acct_Alice); 

    SDPT_UTXO::Account Acct_Bob;  
    SDPT_UTXO::FetchAccount(Acct_Bob, "Bob.account"); 
    //SDPT_UTXO::PrintAccount(Acct_Bob); 

    SDPT_UTXO::Account Acct_Carl;  
    SDPT_UTXO::FetchAccount(Acct_Carl, "Carl.account"); 
    //SDPT_UTXO::PrintAccount(Acct_Carl); 

    SDPT_UTXO::Account Acct_David;
    SDPT_UTXO::FetchAccount(Acct_David, "David.account");
    //SDPT_UTXO::PrintAccount(Acct_David);

    SDPT_UTXO::Account Acct_Eve;
    SDPT_UTXO::FetchAccount(Acct_Eve, "Eve.account");
    //SDPT_UTXO::PrintAccount(Acct_Eve);

    SDPT_UTXO::Account Acct_Frank;
    SDPT_UTXO::FetchAccount(Acct_Frank, "Frank.account");
    //SDPT_UTXO::PrintAccount(Acct_Frank);

    SDPT_UTXO::Account Acct_Grace;
    SDPT_UTXO::FetchAccount(Acct_Grace, "Grace.account");
    //SDPT_UTXO::PrintAccount(Acct_Grace);

    SDPT_UTXO::Account Acct_Henry;
    SDPT_UTXO::FetchAccount(Acct_Henry, "Henry.account");
    //SDPT_UTXO::PrintAccount(Acct_Henry);

    SDPT_UTXO::Account Acct_Ida;
    SDPT_UTXO::FetchAccount(Acct_Ida, "Ida.account");
    //SDPT_UTXO::PrintAccount(Acct_Ida);

    SDPT_UTXO::Account Acct_Jack;
    SDPT_UTXO::FetchAccount(Acct_Jack, "Jack.account");
    //SDPT_UTXO::PrintAccount(Acct_Jack);

    SDPT_UTXO::Account Acct_Kate;
    SDPT_UTXO::FetchAccount(Acct_Kate, "Kate.account");
    //SDPT_UTXO::PrintAccount(Acct_Kate);

    SDPT_UTXO::Account Acct_Leo;
    SDPT_UTXO::FetchAccount(Acct_Leo, "Leo.account");
    //SDPT_UTXO::PrintAccount(Acct_Leo);

    SDPT_UTXO::Account Acct_Mary;
    SDPT_UTXO::FetchAccount(Acct_Mary, "Mary.account");
    //SDPT_UTXO::PrintAccount(Acct_Mary);

    SDPT_UTXO::Account Acct_Nick;
    SDPT_UTXO::FetchAccount(Acct_Nick, "Nick.account");
    //SDPT_UTXO::PrintAccount(Acct_Nick);

    SDPT_UTXO::Account Acct_Olivia;
    SDPT_UTXO::FetchAccount(Acct_Olivia, "Olivia.account");
    //SDPT_UTXO::PrintAccount(Acct_Olivia);

    SDPT_UTXO::Account Acct_Paul;
    SDPT_UTXO::FetchAccount(Acct_Paul, "Paul.account");
    //SDPT_UTXO::PrintAccount(Acct_Paul);

    SDPT_UTXO::Account Acct_Tax;  
    SDPT_UTXO::FetchAccount(Acct_Tax, "Tax.account"); 
    //SDPT_UTXO::PrintAccount(Acct_Tax); 


    std::cout << "begin to the test of 1-to-1 anonymous tx" << std::endl;
    PrintSplitLine('-'); 

    std::cout << "case 1: 1st valid 1-to-1 anonymous tx" << std::endl;

    std::vector<SDPT_UTXO::Coin> AnonSetList;
    // std::cout << "Alice is going to transfer " << BN_bn2dec(v.bn_ptr) << " coins to Bob" << std::endl;
    
    //std::string namelist[9]={Acct_Alice,Acct_Bob,Acct_Carl,Acct_David,Acct_Eve,Acct_Frank,Acct_Grace,Acct_Henry,Acct_Tax};
    std::vector<SDPT_UTXO::Account> acountlist{Acct_Alice, Acct_Bob, Acct_Carl, Acct_David,
                                Acct_Eve, Acct_Frank, Acct_Grace, Acct_Henry,
                                Acct_Ida, Acct_Jack, Acct_Kate, Acct_Leo, Acct_Mary,
                                Acct_Nick, Acct_Olivia, Acct_Paul, Acct_Tax};

    std::set<size_t> senderindex;
    for(auto i = 0; ; i++)
    {
        srand(time(0));
        size_t index = SDPT_UTXO::getranindex(ringnumber);
        if(senderindex.find(index) == senderindex.end())
        {
            senderindex.insert(index);
        }
        if(senderindex.size() == num_sender)
        {
            break;
        }
    }
    std::vector<size_t> senderindexlist(senderindex.begin(), senderindex.end());
    std::sort(senderindexlist.begin(), senderindexlist.end());
    std::vector<SDPT_UTXO::Account> senderlist;
    size_t j = 0;
    AnonSetList.resize(ringnumber);
    std::vector<BigInt> v;
    std::vector<BigInt> sk_sender;
    for(auto i = 0; i < ringnumber; i++)
    {
        if(senderindex.find(i) != senderindex.end())
        {
            senderlist.push_back(acountlist[i]); 
            sk_sender.push_back(acountlist[i].sk);
            v.push_back(acountlist[i].m);
        }
        AnonSetList[i].pk = acountlist[i].pk;
        AnonSetList[i].coin_tx = acountlist[i].coin_ct;
    }
    std::vector<ECPoint> pk_receiver(num_receiver);
    //generate the  random receiver pk
    for(auto i = 0; i < num_receiver; i++)
    {
       std::tie(pk_receiver[i], std::ignore) = TwistedExponentialElGamal::KeyGen(pp.enc_part);
    }
    SDPT_UTXO::AnonTransaction anon_transaction = SDPT_UTXO::CreateAnonTransaction(pp, senderlist, v, pk_receiver, AnonSetList, sk_sender, count);
   

}

int main()
{
    CRYPTO_Initialize();  
    // the ringnumber = the participants in the transaction, now we support the maximum >=2, had better set the ringnumber= 2^n
    //we only test the maximum=64, if set ringnumber >64, maybe is is also ok
    size_t ringnumber=8;
    size_t num_sender=2;
    size_t num_receiver=2;
    Build_SDPT_Test_Enviroment(ringnumber); 
    Emulate_SDPT_System(ringnumber, num_sender, num_receiver);
    CRYPTO_Finalize(); 

    return 0; 
}



