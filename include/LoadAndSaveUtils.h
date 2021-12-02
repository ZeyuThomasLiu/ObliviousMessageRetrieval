#pragma once

#include<iostream>
#include<fstream>
#include<string>
#include<experimental/filesystem>
using namespace std;

void createDatabase(int num_of_transactions = 524288, int payloadSize = 306){
    for(int i = 0; i < num_of_transactions; i++){
        ofstream datafile;
        auto tempi = i % 65537;
        datafile.open ("../data/payloads/"+to_string(i)+".txt");
        for(int j = 0; j < payloadSize; j++){
            datafile << (65537 - tempi+j)%65537 << "\n";
        }
        datafile.close();
    }
}

vector<uint64_t> loadDataSingle(int i, int payloadSize = 306){
    vector<uint64_t> ret;

    ret.resize(payloadSize);
    ifstream datafile;
    datafile.open ("../data/payloads/"+to_string(i)+".txt");
    for(int j = 0; j < payloadSize; j++){
        datafile >> ret[j];
    }
    datafile.close();

    return ret;
}

void saveClues(const PVWCiphertext& clue, int transaction_num){
    ofstream datafile;
    datafile.open ("../data/clues/"+to_string(transaction_num)+".txt");

    for(size_t i = 0; i < clue.a.GetLength(); i++){
        datafile << clue.a[i].ConvertToInt() << "\n";
    }
    for(size_t i = 0; i < clue.b.GetLength(); i++){
        datafile << clue.b[i].ConvertToInt() << "\n";
    }

    datafile.close();
}

void loadData(vector<vector<uint64_t>>& msgs, const int& start, const int& end, int payloadSize = 306){
    msgs.resize(end-start);
    for(int i = start; i < end; i++){
        msgs[i-start].resize(payloadSize);
        ifstream datafile;
        datafile.open("../data/payloads/"+to_string(i)+".txt");
        for(int j = 0; j < payloadSize; j++){
            datafile >> msgs[i-start][j];
        }
        datafile.close();
    }
}

void loadClues(vector<PVWCiphertext>& clues, const int& start, const int& end, const PVWParam& param){
    clues.resize(end-start);
    for(int i = start; i < end; i++){
        clues[i-start].a = NativeVector(param.n);
        clues[i-start].b = NativeVector(param.ell);

        ifstream datafile;
        datafile.open ("../data/clues/"+to_string(i)+".txt");

        for(int j = 0; j < param.n; j++){
            uint64_t temp;
            datafile >> temp;
            clues[i-start].a[j] = temp;
        }

        for(int j = 0; j < param.ell; j++){
            uint64_t temp;
            datafile >> temp;
            clues[i-start].b[j] = temp;
        }
    }
}