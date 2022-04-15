#pragma once
#include "include/PVWToBFVSeal.h"
#include "include/SealUtils.h"
#include "include/retrieval.h"
#include "include/client.h"
#include "include/LoadAndSaveUtils.h"
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>

// Public
const size_t plaintextModulus = 65537;
const size_t poly_modulus_degree_OMR = 8192;
struct PublicParams{
    PVWParam ClueParam;
    SEALContext DetectionParam;
    SEALContext DetectionParam_level3;
    SEALContext DetectionParam_level2;
    size_t degree;
    size_t payloadSize;
    int numOfTransactions;
    int numBuckets;
    int numRep;

    PublicParams(int n, int q, double std_dev, int m, int ell,
                    EncryptionParameters BFVparam, EncryptionParameters BFVparam3, EncryptionParameters BFVparam2, 
                    size_t degree, size_t payloadSize, int numOfTransactions, int numBuckets, int numRep)
        : ClueParam(n, q, std_dev, m, ell), DetectionParam(BFVparam, true, sec_level_type::none),
        DetectionParam_level3(BFVparam3, true, sec_level_type::none), DetectionParam_level2(BFVparam2, true, sec_level_type::none),
        degree(degree), payloadSize(payloadSize), numOfTransactions(numOfTransactions),
        numBuckets(numBuckets), numRep(numRep){
            if(payloadSize & 1){
                payloadSize += 1;
                std::cerr << "Padding payload size to the nearest even number that is > the current input payload size\n";
            }
        }
};

PublicParams initializeParameters(int numOfTransactions, size_t payloadSize, int numBuckets, int numRep);

// For Senders
struct SingleDatabaseBlock{
    PVWCiphertext clue;
    vector<uint64_t> payload;
};

// For Recipients
typedef vector<PVWCiphertext> ClueKey;
struct PrivateKeySet{
    PVWsk ClueSK;
    SecretKey DetectionSK;
};

// For Detectors
struct TheDigest{
    vector<Ciphertext> DigestedIdx;
    vector<Ciphertext> DigestedPayload;
};

// For Recipients&Detectors
class DetectionKeySet{
    public:
        vector<Ciphertext> SwitchingKey;
        GaloisKeys RotKey;
        GaloisKeys RotKey3;
        GaloisKeys RotKey2;
        RelinKeys RLK;
        PublicKey PK;

        DetectionKeySet(){};
        ~DetectionKeySet(){};
};

// Sender class
class Sender{
    public:
        Sender(){};
        ~Sender(){};
        void GenerateClue(PVWCiphertext& clue, const ClueKey& pk, const PublicParams& param);
        void StreamClue(stringstream& stream, const PVWCiphertext& clue, const PublicParams& param);
};

// Recipient class
class Recipient{
    public:
        ClueKey cluePK;
        DetectionKeySet detectKey;

        Recipient(){};
        Recipient(const PublicParams& param){};
        ~Recipient(){};
        void GeneratePrivateKey(const PublicParams& param);
        void GeneratePublicKey(const PublicParams& param);
        void StreamDetectionKeySet(const PublicParams& param, vector<stringstream>& stream);
        void DecodeDigest(vector<vector<long>> &decodedMsg, const TheDigest& msg, const PublicParams& param, int seed);

    private:
        PrivateKeySet sk;
};

// Detector class
class Detector{
    public:
        vector<SingleDatabaseBlock> database;
        map<string, DetectionKeySet> clientKeys;

        Detector(){};
        Detector(const PublicParams& param);
        ~Detector(){};
        void ObtainDetectionKeyFromRecipientStream(const PublicParams& param, vector<stringstream>& stream, const string& clientName);
        void GenerateDigestedMsgFromDatabase(TheDigest& msg, const string& clientName, const PublicParams& param, int numcores, int seed,
                                            void (*loadClue)  (vector<PVWCiphertext>&, const int&, const int&, const PVWParam&),
                                            void (*loadData) (vector<vector<uint64_t>>&, const int&, const int&, int));
        void StreamDigestedMsg(vector<stringstream>& streamIdx, vector<stringstream>& streamPld, const TheDigest& msg);
};

//////////////////////////////////////////////////////

vector<vector<uint64_t>> preparinngTransactionsFormal(PVWpk& pk, 
                                                    int numOfTransactions, int pertinentMsgNum, const PVWParam& params, bool formultitest = false){
    srand (time(NULL));

    vector<int> msgs(numOfTransactions);
    vector<vector<uint64_t>> ret;
    vector<int> zeros(params.ell, 0);

    for(int i = 0; i < pertinentMsgNum;){
        auto temp = rand() % numOfTransactions;
        while(msgs[temp]){
            temp = rand() % numOfTransactions;
        }
        msgs[temp] = 1;
        i++;
    }

    cout << "Expected Message Indices: ";

    for(int i = 0; i < numOfTransactions; i++){
        PVWCiphertext tempclue;
        if(msgs[i]){
            cout << i << " ";
            PVWEncPK(tempclue, zeros, pk, params);
            ret.push_back(loadDataSingle(i));
            expectedIndices.push_back(uint64_t(i));
        }
        else
        {
            auto sk2 = PVWGenerateSecretKey(params);
            PVWEncSK(tempclue, zeros, sk2, params);
        }

        saveClues(tempclue, i);
    }
    cout << endl;
    return ret;
}

// to check whether the result is as expected
bool checkRes(vector<vector<uint64_t>> expected, vector<vector<long>> res){
    for(size_t i = 0; i < expected.size(); i++){
        bool flag = false;
        for(size_t j = 0; j < res.size(); j++){
            if(expected[i][0] == uint64_t(res[j][0])){
                if(expected[i].size() != res[j].size())
                {
                    cerr << "expected and res length not the same" << endl;
                    return false;
                }
                for(size_t k = 1; k < res[j].size(); k++){
                    if(expected[i][k] != uint64_t(res[j][k]))
                        break;
                    if(k == res[j].size() - 1){
                        flag = true;
                    }
                }
            }
        }
        if(!flag)
            return false;
    }
    return true;
}

///////////////////////////////// Implementation ////////////////////////////////////

PublicParams initializeParameters(int numOfTransactions, size_t payloadSize, int numBuckets, int numRep){
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = poly_modulus_degree_OMR;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 
                                                                            39, 60, 60, 60, 60, 
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(plaintextModulus);

	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    /////////////////////////////////////// Level specific context
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    parms_next.set_random_generator(rng);
    //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 2, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    parms_last.set_random_generator(rng);
    ////////////////////////////////////////////////////////
    
    return PublicParams(450, plaintextModulus, 1.3, 16000, 4, parms, parms_next, parms_last,
            poly_modulus_degree, payloadSize, numOfTransactions, numBuckets, numRep);
}

///////////////////////////////////////////
// Sender
//////////////////////////////////////////


void Sender::GenerateClue(PVWCiphertext& clue, const ClueKey& pk, const PublicParams& param){
    vector<int> zeros(param.ClueParam.ell, 0);
    PVWEncPK(clue, zeros, pk, param.ClueParam);
    return;
}

void Sender::StreamClue(stringstream& stream, const PVWCiphertext& clue, const PublicParams& param){

    for(size_t i = 0; i < clue.a.GetLength(); i++){
        auto temp = clue.a[i].ConvertToInt();
        if(temp < 1000)
            stream << '0';
        if(temp < 100)
            stream << '0';
        if(temp < 10)
            stream << '0';
        if(temp < 1)
            stream << '0';
        stream << temp;
    }
    for(size_t i = 0; i < clue.b.GetLength(); i++){
        auto temp = clue.b[i].ConvertToInt();
        if(temp < 1000)
            stream << '0';
        if(temp < 100)
            stream << '0';
        if(temp < 10)
            stream << '0';
        if(temp < 1)
            stream << '0';
        stream << temp;
    }
    return;
}


///////////////////////////////////////////
// Recipient
///////////////////////////////////////////


void Recipient::GeneratePrivateKey(const PublicParams& param){
    this->sk.ClueSK = PVWGenerateSecretKey(param.ClueParam);
    KeyGenerator keygen(param.DetectionParam);
    this->sk.DetectionSK = keygen.secret_key();
}

void Recipient::GeneratePublicKey(const PublicParams& param){
    this->cluePK = PVWGeneratePublicKey(param.ClueParam, this->sk.ClueSK);

    KeyGenerator keygen(param.DetectionParam, this->sk.DetectionSK);
    keygen.create_public_key(this->detectKey.PK);
    keygen.create_relin_keys(this->detectKey.RLK);
    keygen.create_galois_keys(vector<int>({1}), this->detectKey.RotKey);

    auto coeff_modulus = CoeffModulus::Create(param.degree, { 28, 
                                                                39, 60, 60, 60, 60, 
                                                                60, 60, 60, 60, 60, 60,
                                                                32, 30, 60 });
    /////////////////////////////////////// Level specific keys
    vector<int> coeff_modulus_next(15);
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * param.degree);
    sk_next.parms_id() = param.DetectionParam_level3.key_parms_id();
    util::set_poly(this->sk.DetectionSK.data().data(), param.degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        this->sk.DetectionSK.data().data() + param.degree * (coeff_modulus.size() - 1), param.degree, 1,
        sk_next.data().data() + param.degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(param.DetectionParam_level3, sk_next); 
    vector<int> steps_next = {0,1};
    keygen_next.create_galois_keys(steps_next, this->detectKey.RotKey3);
        //////////////////////
    vector<int> coeff_modulus_last(15);
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 2, coeff_modulus_last.end()-1);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * param.degree);
    sk_last.parms_id() = param.DetectionParam_level2.key_parms_id();
    util::set_poly(this->sk.DetectionSK.data().data(), param.degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        this->sk.DetectionSK.data().data() + param.degree * (coeff_modulus.size() - 1), param.degree, 1,
        sk_last.data().data() + param.degree * (coeff_modulus_last.size() - 1));
    KeyGenerator keygen_last(param.DetectionParam_level2, sk_last); 
    vector<int> steps = {0};
    for(int i = 1; i < int(param.degree/2); i *= 2){
	    steps.push_back(i);
    }
    keygen_last.create_galois_keys(steps, this->detectKey.RotKey2);
    ////////////////////////////////////////////////////////////////////////////

    this->detectKey.SwitchingKey.resize(param.ClueParam.ell);
    genSwitchingKeyPVWPacked(this->detectKey.SwitchingKey, param.DetectionParam, 
                                        param.degree, this->detectKey.PK, 
                                                sk.DetectionSK, sk.ClueSK, param.ClueParam);
}

void Recipient::StreamDetectionKeySet(const PublicParams& param, vector<stringstream>& stream){
    KeyGenerator keygen(param.DetectionParam, this->sk.DetectionSK);
    PublicKey PK;
    keygen.create_public_key(PK);
    RelinKeys RLK;
    keygen.create_relin_keys(RLK);
    seal::Serializable<GaloisKeys> RotKey = keygen.create_galois_keys(vector<int>({1}));

    auto coeff_modulus = CoeffModulus::Create(param.degree, { 28, 
                                                                39, 60, 60, 60, 60, 
                                                                60, 60, 60, 60, 60, 60,
                                                                32, 30, 60 });
    /////////////////////////////////////// Level specific keys
    vector<int> coeff_modulus_next(15);
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * param.degree);
    sk_next.parms_id() = param.DetectionParam_level3.key_parms_id();
    util::set_poly(this->sk.DetectionSK.data().data(), param.degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        this->sk.DetectionSK.data().data() + param.degree * (coeff_modulus.size() - 1), param.degree, 1,
        sk_next.data().data() + param.degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(param.DetectionParam_level3, sk_next); 
    vector<int> steps_next = {0,1};
    seal::Serializable<GaloisKeys> RotKey3 = keygen_next.create_galois_keys(steps_next);
        //////////////////////
    vector<int> coeff_modulus_last(15);
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 2, coeff_modulus_last.end()-1);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * param.degree);
    sk_last.parms_id() = param.DetectionParam_level2.key_parms_id();
    util::set_poly(this->sk.DetectionSK.data().data(), param.degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        this->sk.DetectionSK.data().data() + param.degree * (coeff_modulus.size() - 1), param.degree, 1,
        sk_last.data().data() + param.degree * (coeff_modulus_last.size() - 1));
    KeyGenerator keygen_last(param.DetectionParam_level2, sk_last); 
    vector<int> steps = {0};
    for(int i = 1; i < int(param.degree/2); i *= 2){
	    steps.push_back(i);
    }
    seal::Serializable<GaloisKeys> RotKey2 = keygen_last.create_galois_keys(steps);
    ////////////////////////////////////////////////////////////////////////////

    auto SwitchingKey = genSwitchingKeyPVWPacked(param.DetectionParam, param.degree, this->detectKey.PK, 
                                                sk.DetectionSK, sk.ClueSK, param.ClueParam);

    stream.resize(SwitchingKey.size() + 5);
    for(size_t i = 0; i < SwitchingKey.size(); i++){
        SwitchingKey[i].save(stream[i]);
    }
    RotKey.save(stream[SwitchingKey.size() + 0]);
    RotKey3.save(stream[SwitchingKey.size() + 1]);
    RotKey2.save(stream[SwitchingKey.size() + 2]);
    RLK.save(stream[SwitchingKey.size() + 3]);
    PK.save(stream[SwitchingKey.size() + 4]);
}

void Recipient::DecodeDigest(vector<vector<long>> &decodedMsg, const TheDigest& msg, 
                        const PublicParams& param, int seed){
    vector<vector<int>> bipartite_map;
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map, weights, param.numOfTransactions,
                                        param.numBuckets, param.numRep, seed);
    
    // 1. find pertinent indices
    map<int, int> pertinentIndices;
    for(size_t i = 0; i < msg.DigestedIdx.size(); i++){
        map<int, int> temp;
        decodeIndices(temp, msg.DigestedIdx[i], param.numOfTransactions, 
                                param.degree, this->sk.DetectionSK, param.DetectionParam);
        pertinentIndices.insert(temp.begin(), temp.end());
    }

    // cout << "Resulted pertinent indices: ";
    // for (map<int, int>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    // {
    //     std::cout << it->first << " ";  // print out all the indices found
    // }
    // cout << std::endl;
    
    // 2. forming rhs
    vector<vector<int>> rhs;
    formRhs(rhs, msg.DigestedPayload, this->sk.DetectionSK, 
                param.degree, param.DetectionParam, param.numBuckets,
                param.payloadSize/2);
    // 3. forming lhs
    vector<vector<int>> lhs;
    formLhsWeights(lhs, pertinentIndices, bipartite_map, weights, param.numBuckets);

    // 4. solving equation
    decodedMsg = equationSolving(lhs, rhs, param.payloadSize/2);
}


///////////////////////////////////////////
// Detector
///////////////////////////////////////////


void Detector::ObtainDetectionKeyFromRecipientStream(const PublicParams& param, vector<stringstream>& stream, const string& clientName){
    clientKeys[clientName] = DetectionKeySet();
    clientKeys[clientName].SwitchingKey.resize(param.ClueParam.ell);
    for(int i = 0; i < param.ClueParam.ell; i++){
        clientKeys[clientName].SwitchingKey[i].load(param.DetectionParam, stream[i]);
    }
    clientKeys[clientName].RotKey.load(param.DetectionParam, stream[param.ClueParam.ell + 0]);
    clientKeys[clientName].RotKey3.load(param.DetectionParam_level3, stream[param.ClueParam.ell + 1]);
    clientKeys[clientName].RotKey2.load(param.DetectionParam_level2, stream[param.ClueParam.ell + 2]);
    clientKeys[clientName].RLK.load(param.DetectionParam, stream[param.ClueParam.ell + 3]);
    clientKeys[clientName].PK.load(param.DetectionParam, stream[param.ClueParam.ell + 4]);
};

Ciphertext serverPackingSIC(vector<PVWCiphertext>& SICPVW, vector<Ciphertext> switchingKey, const RelinKeys& relin_keys,
                            const GaloisKeys& gal_keys, const size_t& degree, const SEALContext& context, const PVWParam& params){
    Evaluator evaluator(context);
    
    vector<Ciphertext> packedSIC(params.ell);
    computeBplusASPVWOptimized(packedSIC, SICPVW, switchingKey, gal_keys, context, params);

    int rangeToCheck = 850; // range check is from [-rangeToCheck, rangeToCheck-1]
    newRangeCheckPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);

    return packedSIC[0];
}

void serverPackingDigest(Ciphertext& lhs, Ciphertext& rhs, vector<vector<int>>& bipartite_map, vector<vector<int>>& weights,
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const GaloisKeys& gal_keys, const GaloisKeys& gal_keys_lower,
                        const size_t& degree, const SEALContext& context, const SEALContext& context2, const PVWParam& params, const int numOfTransactions, 
                        int& counter){

    Evaluator evaluator(context);
    int step = 32; // simply to save memory so process 32 msgs at a time
    
    for(int i = counter; i < counter+numOfTransactions; i += step){
        vector<Ciphertext> expandedSIC;
        // step 1. expand PV
        expandSIC(expandedSIC, packedSIC, gal_keys, gal_keys_lower, int(degree), context, context2, step, i-counter);

        // transform to ntt form for better efficiency especially for the last two steps
        for(size_t j = 0; j < expandedSIC.size(); j++)
            if(!expandedSIC[j].is_ntt_form())
                evaluator.transform_to_ntt_inplace(expandedSIC[j]);

        // step 2. deterministic retrieval
        deterministicIndexRetrieval(lhs, expandedSIC, context, degree, i);

        // step 3-4. multiply weights and pack them
        // The following two steps are for streaming updates
        vector<vector<Ciphertext>> payloadUnpacked;
        payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, degree, i, i - counter);
        
        // Note that if number of repeatitions is already set, this is the only step needed for streaming updates
        payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);   
    }
    if(lhs.is_ntt_form())
        evaluator.transform_from_ntt_inplace(lhs);
    if(rhs.is_ntt_form())
        evaluator.transform_from_ntt_inplace(rhs);

    counter += numOfTransactions;
}

void Detector::GenerateDigestedMsgFromDatabase(TheDigest& msg, const string& clientName, 
                                        const PublicParams& param, int numcores, int seed,
                                        void (*loadClue)  (vector<PVWCiphertext>&, const int&, const int&, const PVWParam&),
                                        void (*loadData) (vector<vector<uint64_t>>&, const int&, const int&, int)){
    // 0. Prepare
    vector<int> counter(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    Evaluator evaluator(param.DetectionParam);
    vector<Ciphertext> lhs_multi(numcores), rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);
    vector<vector<vector<int>>> weights(numcores);

    // 1. Obtain SIC
    auto size_per_core_per_ciphertext = param.numOfTransactions/numcores/param.degree;
    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(size_per_core_per_ciphertext)); 
        // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed
    NTL::SetNumThreads(numcores);
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        counter[i] = param.numOfTransactions/numcores*i;
        size_t j = 0;
        while(j < param.numOfTransactions/numcores/param.degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;
            loadClue(SICPVW_multicore[i], counter[i], counter[i]+param.degree, param.ClueParam); 
                // Note that we load one batch at a time, because database in usually to large to be stored in memory
                // This function needs to be modified by applicaiton
            
            packedSICfromPhase1[i][j] = serverPackingSIC(SICPVW_multicore[i], clientKeys[clientName].SwitchingKey, clientKeys[clientName].RLK, 
                                                            clientKeys[clientName].RotKey, param.degree, param.DetectionParam, param.ClueParam);
            
            j++;
            counter[i] += param.degree;
            SICPVW_multicore[i].clear();
        }
        
    }
    NTL_EXEC_RANGE_END;

    for(int i = 0; i < numcores; i++){
        bipartiteGraphWeightsGeneration(bipartite_map[i], weights[i], 
                                        param.numOfTransactions, param.numBuckets, param.numRep, seed);
    }

    // 2. Compute digest from SIC
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        size_t j = 0;
        counter[i] = param.numOfTransactions/numcores*i;

        while(j < param.numOfTransactions/numcores/param.degree){
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+param.degree, param.payloadSize/2);

            Ciphertext templhs, temprhs;
            serverPackingDigest(templhs, temprhs, bipartite_map[0], weights[0],
                            packedSICfromPhase1[i][j], payload_multicore[i], 
                            clientKeys[clientName].RotKey3, clientKeys[clientName].RotKey2,
                            param.degree, param.DetectionParam_level3, param.DetectionParam_level2, 
                            param.ClueParam, param.degree, counter[i]);
            if(j == 0){
                lhs_multi[i] = templhs;
                rhs_multi[i] = temprhs;
            } else {
                evaluator.add_inplace(lhs_multi[i], templhs);
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++){
        evaluator.add_inplace(lhs_multi[0], lhs_multi[i]);
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while(param.DetectionParam.last_parms_id() != lhs_multi[0].parms_id()){
        evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
        evaluator.mod_switch_to_next_inplace(lhs_multi[0]);
    }

    // Obtain the result
    msg.DigestedIdx.push_back(lhs_multi[0]);
    msg.DigestedPayload.push_back(rhs_multi[0]);
}

void Detector::StreamDigestedMsg(vector<stringstream>& streamIdx, vector<stringstream>& streamPld, const TheDigest& msg){
    streamIdx.resize(msg.DigestedIdx.size());
    streamPld.resize(msg.DigestedPayload.size());
    for(size_t i = 0; i < streamIdx.size(); i++){
        msg.DigestedIdx[i].save(streamIdx[i]);
    }
    for(size_t i = 0; i < streamPld.size(); i++){
        msg.DigestedPayload[i].save(streamPld[i]);
    }
}