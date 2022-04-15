#include "APIs.h"

int main(){
    auto numOfTransactions = poly_modulus_degree_OMR;
    int numBuckets = 20; // Number of buckets. Should be <= poly_modulus_degree_OMR*2 / payload_size
    int numRep = 5; // Number of repeatition. 5 is generally enough.

    int numPerti = 10; // Number of pertinent messages for tests

    // Initialize parameters
    PublicParams testParam = initializeParameters(numOfTransactions, 612, numBuckets, numRep);

    // Initialize recipient
    Recipient recip;
    recip.GeneratePrivateKey(testParam);
    recip.GeneratePublicKey(testParam);
    vector<stringstream> stream;
    recip.StreamDetectionKeySet(testParam, stream);

    // Generate transactions, including clues
    auto expected = preparinngTransactionsFormal(recip.cluePK, numOfTransactions, numPerti,  testParam.ClueParam);

    // Initialize detector
    Detector dec;
    TheDigest dgt;
    dec.ObtainDetectionKeyFromRecipientStream(testParam, stream, "A");
    dec.GenerateDigestedMsgFromDatabase(dgt, "A", testParam, 1, 3, &loadClues, &loadData);

    // Decode msg
    vector<vector<long>> decodedMsg;
    recip.DecodeDigest(decodedMsg, dgt, testParam, 3);

    // Test correctness
    if(checkRes(expected, decodedMsg))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}