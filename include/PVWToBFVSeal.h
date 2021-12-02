#pragma once

#include "regevEncryption.h"
#include "seal/seal.h"
#include <NTL/BasicThreadPool.h>
#include "global.h"
using namespace seal;

// takes a vector of ciphertexts, and mult them all together result in the first element of the vector
// depth optimal using tree-shaped method
inline
void EvalMultMany_inpace(vector<Ciphertext>& ciphertexts, const RelinKeys &relin_keys, const SEALContext& context){ // TODOmulti: can be multithreaded easily
    Evaluator evaluator(context);
    int counter = 0;

    while(ciphertexts.size() != 1){
        counter += 1;
        for(size_t i = 0; i < ciphertexts.size()/2; i++){
            evaluator.multiply_inplace(ciphertexts[i], ciphertexts[ciphertexts.size()/2+i]);
            evaluator.relinearize_inplace(ciphertexts[i], relin_keys);
            if(counter & 1)
                evaluator.mod_switch_to_next_inplace(ciphertexts[i]);
        }
        if(ciphertexts.size()%2 == 0)
            ciphertexts.resize(ciphertexts.size()/2);
        else{ // if odd, take the last one and mod down to make them compatible
            ciphertexts[ciphertexts.size()/2] = ciphertexts[ciphertexts.size()-1];
            if(counter & 1)
                evaluator.mod_switch_to_next_inplace(ciphertexts[ciphertexts.size()/2]);
            ciphertexts.resize(ciphertexts.size()/2+1);
        }
    }
}

// innersum up to toCover amount, O(log(toCover)) time
void innerSum_inplace(Ciphertext& output, const GaloisKeys& gal_keys, const size_t& degree,
                const size_t& toCover, const SEALContext& context){
    Evaluator evaluator(context);
    for(size_t i = 1; i < toCover; i*=2){
        Ciphertext temp;
        if(i == degree/2)
        {
            evaluator.rotate_columns(output, gal_keys, temp);
            evaluator.add_inplace(output, temp);
        }
        else
        {
            evaluator.rotate_rows(output, i, gal_keys, temp);
            evaluator.add_inplace(output, temp);
        }
    }
}

// Takes one SIC compressed and expand then into SIC's each encrypt 0/1 in slots up to toExpandNum
void expandSIC(vector<Ciphertext>& expanded, Ciphertext& toExpand, const GaloisKeys& gal_keys,
                const size_t& degree, const SEALContext& context, const SEALContext& context2, const size_t& toExpandNum, const size_t& start = 0){ 
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    expanded.resize(toExpandNum);

    vector<uint64_t> pod_matrix(degree, 0ULL); 
    pod_matrix[0] = 1ULL;
    Plaintext plain_matrix;
    batch_encoder.encode(pod_matrix, plain_matrix);
    for(size_t i = 0; i < toExpandNum; i++){ 
	    if((i+start) != 0){ 
            // rotate one slot at a time
            if((i+start) == degree/2){
                evaluator.rotate_columns_inplace(toExpand, gal_keys);
                evaluator.rotate_rows_inplace(toExpand, 1, gal_keys); 
            }
            else{
                evaluator.rotate_rows_inplace(toExpand, 1, gal_keys); 
            }
        }
        // extract the first slot
        evaluator.multiply_plain(toExpand, plain_matrix, expanded[i]);
	    evaluator.mod_switch_to_next_inplace(expanded[i]);
	    evaluator.mod_switch_to_next_inplace(expanded[i]);
        // populate to all slots
        innerSum_inplace(expanded[i], gal_keys_last, degree, degree, context2); 
    }
}

// take PVW sk's and output switching key, which is a ciphertext of size \ell*n, where n is the PVW secret key dimension
void genSwitchingKeyPVWPacked(vector<Ciphertext>& switchingKey, const SEALContext& context, const size_t& degree, 
                         const PublicKey& BFVpk, const SecretKey& BFVsk, const PVWsk& regSk, const PVWParam& params){ // TODOmulti: can be multithreaded easily
    
    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, BFVpk);
    // Use symmetric encryption to enable seed mode to reduce the detection key size
    encryptor.set_secret_key(BFVsk);

    int tempn = 1;
    for(tempn = 1; tempn < params.n; tempn *= 2){}
    for(int j = 0; j < params.ell; j++){
        // encrypt into ell BFV ciphertexts
        vector<uint64_t> skInt(degree);
        for(size_t i = 0; i < degree; i++){
            auto tempindex = i%uint64_t(tempn);
            if(int(tempindex) >= params.n)
            {
                skInt[i] = 0;
            } else {
                skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % 65537);
            }
        }
        Plaintext plaintext;
        batch_encoder.encode(skInt, plaintext);
        encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
    }
}

// This is the same as the function above but with a return type, for detection key size calculation
vector<seal::Serializable<Ciphertext>> genSwitchingKeyPVWPacked(const SEALContext& context, const size_t& degree, 
                         const PublicKey& BFVpk, const SecretKey& BFVsk, const PVWsk& regSk, const PVWParam& params){ 
    vector<seal::Serializable<Ciphertext>> switchingKey;

    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, BFVpk);
    encryptor.set_secret_key(BFVsk);

    int tempn = 1;
    for(tempn = 1; tempn < params.n; tempn *= 2){}
    for(int j = 0; j < params.ell; j++){
        vector<uint64_t> skInt(degree);
        for(size_t i = 0; i < degree; i++){
            auto tempindex = i%uint64_t(tempn);
            if(int(tempindex) >= params.n)
            {
                skInt[i] = 0;
            } else {
                skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % 65537);
            }
        }
        Plaintext plaintext;
        batch_encoder.encode(skInt, plaintext);
        switchingKey.push_back(encryptor.encrypt_symmetric(plaintext));
    }

    return switchingKey;
}


// compute b - as with packed swk but also only requires one rot key
void computeBplusASPVWOptimized(vector<Ciphertext>& output, \
        const vector<PVWCiphertext>& toPack, vector<Ciphertext>& switchingKey, const GaloisKeys& gal_keys,
        const SEALContext& context, const PVWParam& param){ 
    MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

    int tempn;
    for(tempn = 1; tempn < param.n; tempn*=2){}

    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    if(toPack.size() > slot_count){
        cerr << "Please pack at most " << slot_count << " PVW ciphertexts at one time." << endl;
        return;
    }

    for(int i = 0; i < tempn; i++){
        vector<uint64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            int the_index = (i+int(j))%tempn;
            if(the_index >= param.n)
            {
                vectorOfInts[j] = 0;
            } else {
                vectorOfInts[j] = uint64_t((toPack[j].a[the_index].ConvertToInt()));
            }
        }

        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        
        for(int j = 0; j < param.ell; j++){
            if(i == 0){
                evaluator.multiply_plain(switchingKey[j], plaintext, output[j]); // times s[i]
            }
            else{
                Ciphertext temp;
                evaluator.multiply_plain(switchingKey[j], plaintext, temp);
                evaluator.add_inplace(output[j], temp);
            }
            // rotate one slot at a time
            evaluator.rotate_rows_inplace(switchingKey[j], 1, gal_keys);
        }
    }

    for(int i = 0; i < param.ell; i++){
        vector<uint64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            vectorOfInts[j] = uint64_t((toPack[j].b[i].ConvertToInt() - 16384) % 65537); 
            // 16384 here is due to the implementation of PVW ciphertext. Needs to shift by ~q/4 so that the decryption is around 0
        }
        Plaintext plaintext;

        batch_encoder.encode(vectorOfInts, plaintext);
        evaluator.negate_inplace(output[i]);
        evaluator.add_plain_inplace(output[i], plaintext);
        evaluator.mod_switch_to_next_inplace(output[i]); 
    }
    MemoryManager::SwitchProfile(std::move(old_prof));
}

inline
void calUptoDegreeK(vector<Ciphertext>& output, const Ciphertext& input, const int DegreeK, const RelinKeys &relin_keys, const SEALContext& context){
    vector<int> calculated(DegreeK, 0);
    Evaluator evaluator(context);
    output[0] = input;
    calculated[0] = 1; // degree 1, x
    Ciphertext res, base;
    vector<int> numMod(DegreeK, 0);

    for(int i = DegreeK; i > 0; i--){
        if(calculated[i-1] == 0){
            auto toCalculate = i;
            int resdeg = 0;
            int basedeg = 1;
            base = input;
            while(toCalculate > 0){
                if(toCalculate & 1){
                    toCalculate -= 1;
                    resdeg += basedeg;
                    if(calculated[resdeg-1] != 0){
                        res = output[resdeg - 1];
                    } else {
                        if(resdeg == basedeg){
                            res = base; // should've never be used as base should have made calculated[basedeg-1]
                        } else {
                            numMod[resdeg-1] = numMod[basedeg-1];

                            evaluator.mod_switch_to_inplace(res, base.parms_id()); // match modulus
                            evaluator.multiply_inplace(res, base);
                            evaluator.relinearize_inplace(res, relin_keys);
                            while(numMod[resdeg-1] < (ceil(log2(resdeg))/2)){
                                evaluator.mod_switch_to_next_inplace(res);
                                numMod[resdeg-1]+=1;
                            }
                        }
                        output[resdeg-1] = res;
                        calculated[resdeg-1] += 1;
                    }
                } else {
                    toCalculate /= 2;
                    basedeg *= 2;
                    if(calculated[basedeg-1] != 0){
                        base = output[basedeg - 1];
                    } else {
                        numMod[basedeg-1] = numMod[basedeg/2-1];
                        evaluator.square_inplace(base);
                        evaluator.relinearize_inplace(base, relin_keys);
                        while(numMod[basedeg-1] < (ceil(log2(basedeg))/2)){
                                evaluator.mod_switch_to_next_inplace(base);
                                numMod[basedeg-1]+=1;
                            }
                        output[basedeg-1] = base;
                        calculated[basedeg-1] += 1;
                    }
                }
            }
        }
    }

    for(size_t i = 0; i < output.size()-1; i++){
        evaluator.mod_switch_to_inplace(output[i], output[output.size()-1].parms_id()); // match modulus
    }
    return;
}

// Use Paterson-Stockmeyer to perform the range check function
// The implementaion of this function is more hard-coded
// This is because it usess > 500 local BFV ciphertexts
// SEAL library does not free memory naturally
// Therefore, it is taking more memory than needed, and therefore
// the memory grows very fast.
// To avoid using too much RAM,
// we here have to manually create memory pools and free them
// Note that we create memory pools at different places
// Intuitively: let's say we have 128 20-level ciphertexts
// We mod them down to 3-levels, but for SEAL memory pool
// it's still taking 128 20-level ciphertexts memory
// To regain the use of those memory
// we create a memory pool and free the previous ones
// and move those 3-level ciphertexts to the new memory pool
// This is not an ideal solution
// There might be better ways to resolve this problem
inline
void RangeCheck_PatersonStockmeyer(Ciphertext& ciphertext, const Ciphertext& input, int modulus, const size_t& degree,
                                const RelinKeys &relin_keys, const SEALContext& context){
    MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
    auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));

    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    vector<Ciphertext> kCTs(256);
    vector<Ciphertext> temp;
    {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New(true); // manually creating memory pools and desctruct them to avoid using too much memory
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        vector<Ciphertext> temp(128);
        {
            MemoryPoolHandle my_pool2 = MemoryPoolHandle::New(true);
            for(int i = 0; i < 64; i++){
                temp.push_back(Ciphertext(my_pool2));
            }
            {
                MemoryPoolHandle my_pool3 = MemoryPoolHandle::New(true);
                for(int i = 0; i < 64; i++){
                    temp.push_back(Ciphertext(my_pool3));
                }
                calUptoDegreeK(temp, input, 256, relin_keys, context);
                for(size_t j = 0; j < temp.size()-1; j++){ // match to one level left, the one level left is for plaintext multiplication noise
                    for(int i = 0; i < 3; i++){
                        evaluator.mod_switch_to_next_inplace(temp[j]);
                    }
                }
                for(int i = 255; i > 255-32-32; i--){
                    kCTs[i] = temp[i];
                    temp[i].release();
                }
            }
            for(int i = 255-32-32; i > 255-32-32-32-32; i--){
                kCTs[i] = temp[i];
                temp[i].release();
            }
        }
        for(int i = 0; i < 128; i++){
            kCTs[i] = temp[i];
            temp[i].release();
        }
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    vector<Ciphertext> kToMCTs(256);
    calUptoDegreeK(kToMCTs, kCTs[kCTs.size()-1], 256, relin_keys, context);
    for(int i = 0; i < 3; i++){
        evaluator.mod_switch_to_next_inplace(kCTs[kCTs.size()-1]);
    }

    for(int i = 0; i < 256; i++){
        Ciphertext levelSum;
        bool flag = false;
        for(int j = 0; j < 256; j++){
            if(rangeCheckIndices[i*256+j] != 0){
                vector<uint64_t> intInd(degree, rangeCheckIndices[i*256+j]);
                Plaintext plainInd;
                batch_encoder.encode(intInd, plainInd);
                if (!flag){
                    evaluator.multiply_plain(kCTs[j], plainInd, levelSum);
                    flag = true;
                } else {
                    Ciphertext tmp;
                    evaluator.multiply_plain(kCTs[j], plainInd, tmp);
                    evaluator.add_inplace(levelSum, tmp);
                }
            }
        }
        evaluator.mod_switch_to_inplace(levelSum, kToMCTs[i].parms_id()); // mod down the plaintext multiplication noise
        if(i == 0){
            ciphertext = levelSum;
        } else {
            evaluator.multiply_inplace(levelSum, kToMCTs[i - 1]);
            evaluator.relinearize_inplace(levelSum, relin_keys);
            evaluator.add_inplace(ciphertext, levelSum);
        }
    }
    vector<uint64_t> intInd(degree, 1); 
    Plaintext plainInd;
    Ciphertext tmep;
    batch_encoder.encode(intInd, plainInd);
    evaluator.negate_inplace(ciphertext);
    evaluator.add_plain_inplace(ciphertext, plainInd);
    tmep.release();
    for(int i = 0; i < 256; i++){
        kCTs[i].release();
        kToMCTs[i].release();
    }
    MemoryManager::SwitchProfile(std::move(old_prof_larger));
}

// check in range
// if within [-range, range -1], returns 0, and returns random number in p o/w
void newRangeCheckPVW(vector<Ciphertext>& output, const int& range, const RelinKeys &relin_keys,\
                        const size_t& degree, const SEALContext& context, const PVWParam& param, const int upperbound = 64){ // we do one level of recursion, so no more than 4096 elements
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> res(param.ell);

    for(int j = 0; j < param.ell; j++){
        {
            MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
            auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));
            auto tmp1 = output[j];
            // first use range check to obtain 0 and 1
            RangeCheck_PatersonStockmeyer(res[j], tmp1, 65537, degree, relin_keys, context);
            tmp1.release();
        }
    }
    // Multiply them to reduce the false positive rate
    EvalMultMany_inpace(res, relin_keys, context);
    output = res;
}