#pragma once

#include "math/ternaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/discretegaussiangenerator.h"
#include <iostream>
using namespace std;
using namespace lbcrypto;

struct regevParam{
    int n;
    int q;
    double std_dev;
    int m;
    regevParam(){
        n = 450;
        q = 65537;
        std_dev = 1.3;
        m = 16000; 
    }
    regevParam(int n, int q, double std_dev, int m)
    : n(n), q(q), std_dev(std_dev), m(m)
    {}
};

typedef NativeVector regevSK;

struct regevCiphertext{
    NativeVector a;
    NativeInteger b;
};

typedef vector<regevCiphertext> regevPK;

regevSK regevGenerateSecretKey(const regevParam& param);
regevPK regevGeneratePublicKey(const regevParam& param, const regevSK& sk);
void regevEncSK(regevCiphertext& ct, const int& msg, const regevSK& sk, const regevParam& param, const bool& pk_gen = false);
void regevEncPK(regevCiphertext& ct, const int& msg, const regevPK& pk, const regevParam& param);
void regevDec(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param);

/////////////////////////////////////////////////////////////////// Below are implementation

regevSK regevGenerateSecretKey(const regevParam& param){
    int n = param.n;
    int q = param.q;
    lbcrypto::TernaryUniformGeneratorImpl<regevSK> tug;
    return tug.GenerateVector(n, q);
}

void regevEncSK(regevCiphertext& ct, const int& msg, const regevSK& sk, const regevParam& param, const bool& pk_gen){
    NativeInteger q = param.q;
    int n = param.n;
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(q);
    ct.a = dug.GenerateVector(n);
    NativeInteger mu = q.ComputeMu();
    for (int i = 0; i < n; ++i) {
        ct.b += ct.a[i].ModMulFast(sk[i], q, mu);
    }
    ct.b.ModEq(q);
    if(!pk_gen)
        msg? ct.b.ModAddFastEq(3*q/4, q) : ct.b.ModAddFastEq(q/4, q);
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg(param.std_dev);
    ct.b.ModAddFastEq(m_dgg.GenerateInteger(q), q);
}

regevPK regevGeneratePublicKey(const regevParam& param, const regevSK& sk){
    regevPK pk(param.m);
    for(int i = 0; i < param.m; i++){
        regevEncSK(pk[i], 0, sk, param, true);
    }
    return pk;
}

void regevEncPK(regevCiphertext& ct, const int& msg, const regevPK& pk, const regevParam& param){
    NativeInteger q = param.q;
    ct.a = NativeVector(param.n);
    for(size_t i = 0; i < pk.size(); i++){
        if (rand()%2){
            for(int j = 0; j < param.n; j++){
                ct.a[j].ModAddFastEq(pk[i].a[j], q);
            }
            ct.b.ModAddFastEq(pk[i].b, q);
        }
    }
    msg? ct.b.ModAddFastEq(3*q/4, q) : ct.b.ModAddFastEq(q/4, q);
}

void regevDec(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param){
    NativeInteger q = param.q;
    int n = param.n;
    NativeInteger inner(0);
    NativeInteger r = ct.b;
    NativeInteger mu = q.ComputeMu();
    for (int i = 0; i < n; ++i) {
        inner += ct.a[i].ModMulFast(sk[i], q, mu);
    }
    r.ModSubFastEq(inner, q);
    r.ModEq(q);

    msg = (r < q/2)? 0 : 1;
}

///////////////////////////////////////////////////////////
/////////////////////////////////////////// PVW
///////////////////////////////////////////////////////////

struct PVWParam{
    int n;
    int q;
    double std_dev;
    int m;
    int ell;
    PVWParam(){
        n = 450;
        q = 65537;
        std_dev = 1.3;
        m = 16000; 
        ell = 4;
    }
    PVWParam(int n, int q, double std_dev, int m, int ell)
    : n(n), q(q), std_dev(std_dev), m(m), ell(ell)
    {}
};

typedef vector<NativeVector> PVWsk;

struct PVWCiphertext{
    NativeVector a;
    NativeVector b;
};

typedef vector<PVWCiphertext> PVWpk;

PVWsk PVWGenerateSecretKey(const PVWParam& param);
PVWpk PVWGeneratePublicKey(const PVWParam& param, const PVWsk& sk);
void PVWEncSK(PVWCiphertext& ct, const vector<int>& msg, const PVWsk& sk, const PVWParam& param, const bool& pk_gen = false);
void PVWEncPK(PVWCiphertext& ct, const vector<int>& msg, const PVWpk& pk, const PVWParam& param);
void PVWDec(vector<int>& msg, const PVWCiphertext& ct, const PVWsk& sk, const PVWParam& param);

/////////////////////////////////////////////////////////////////// Below are implementation

PVWsk PVWGenerateSecretKey(const PVWParam& param){
    int n = param.n;
    int q = param.q;
    lbcrypto::DiscreteUniformGeneratorImpl<regevSK> dug;
    dug.SetModulus(q);
    PVWsk ret(param.ell);
    for(int i = 0; i < param.ell; i++){
        ret[i] = dug.GenerateVector(n);
    }
    return ret;
}

void PVWEncSK(PVWCiphertext& ct, const vector<int>& msg, const PVWsk& sk, const PVWParam& param, const bool& pk_gen){
    NativeInteger q = param.q;
    int n = param.n;
    int ell = param.ell;
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(q);
    ct.a = dug.GenerateVector(n);
    ct.b = dug.GenerateVector(ell);
    NativeInteger mu = q.ComputeMu();
    for(int j = 0; j < ell; j++){
        ct.b[j] -= ct.b[j];
        for (int i = 0; i < n; ++i) {
            ct.b[j] += ct.a[i].ModMulFast(sk[j][i], q, mu);
        }
        ct.b[j].ModEq(q);

        if(!pk_gen)
            msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
        DiscreteGaussianGeneratorImpl<NativeVector> m_dgg(param.std_dev);
        ct.b[j].ModAddFastEq(m_dgg.GenerateInteger(q), q);
    }
}

PVWpk PVWGeneratePublicKey(const PVWParam& param, const PVWsk& sk){
    PVWpk pk(param.m);
    vector<int> zeros(param.ell, 0);
    for(int i = 0; i < param.m; i++){
        PVWEncSK(pk[i], zeros, sk, param, true);
    }
    return pk;
}

void PVWEncPK(PVWCiphertext& ct, const vector<int>& msg, const PVWpk& pk, const PVWParam& param){
    NativeInteger q = param.q;
    ct.a = NativeVector(param.n);
    ct.b = NativeVector(param.ell);
    for(size_t i = 0; i < pk.size(); i++){
        if (rand()%2){
            for(int j = 0; j < param.n; j++){
                ct.a[j].ModAddFastEq(pk[i].a[j], q);
            }
            for(int j = 0; j < param.ell; j++){
                ct.b[j].ModAddFastEq(pk[i].b[j], q);
            }
        }
    }
    for(int j = 0; j < param.ell; j++){
        msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
    }
}

void PVWDec(vector<int>& msg, const PVWCiphertext& ct, const PVWsk& sk, const PVWParam& param){
    msg.resize(param.ell);
    NativeInteger q = param.q;
    int n = param.n;

    for(int j = 0; j < param.ell; j++){
        NativeInteger inner(0);
        NativeInteger r = ct.b[j];
        NativeInteger mu = q.ComputeMu();
        for (int i = 0; i < n; ++i) {
            inner += ct.a[i].ModMulFast(sk[j][i], q, mu);
        }
        r.ModSubFastEq(inner, q);
        r.ModEq(q);
        msg[j] = (r < q/2)? 0 : 1;
    }
}