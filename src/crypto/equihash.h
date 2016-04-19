// Copyright (c) 2016 Jack Grigg
// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EQUIHASH_H
#define BITCOIN_EQUIHASH_H

#include "crypto/sha256.h"
#include "utilstrencodings.h"

#include "sodium.h"

#include <cstring>
#include <set>
#include <vector>

typedef crypto_generichash_blake2b_state eh_HashState;
typedef uint32_t eh_index;
typedef uint8_t eh_trunc;

struct invalid_params { };

class StepRow
{
protected:
    unsigned char* hash;
    unsigned int len;

public:
    StepRow(unsigned int n, const eh_HashState& base_state, eh_index i);
    ~StepRow();

    StepRow(const StepRow& a);

    void TrimHash(int l);
    bool IsZero();

    friend bool HasCollision(StepRow& a, StepRow& b, int l);
};

bool HasCollision(StepRow& a, StepRow& b, int l);
template<typename INDEX_TYPE>
bool DistinctIndices(const std::vector<INDEX_TYPE>& a, const std::vector<INDEX_TYPE>& b);

class BasicStepRow : public StepRow
{
private:
    std::vector<eh_index> indices;

public:
    BasicStepRow(unsigned int n, const eh_HashState& base_state, eh_index i);
    ~BasicStepRow() { }

    BasicStepRow(const BasicStepRow& a);
    BasicStepRow& operator=(const BasicStepRow& a);
    BasicStepRow& operator^=(const BasicStepRow& a);

    bool IndicesBefore(const BasicStepRow& a) { return indices[0] < a.indices[0]; }
    std::vector<eh_index> GetSolution() { return std::vector<eh_index>(indices); }
    std::string GetHex() { return HexStr(hash, hash+len); }

    friend inline const BasicStepRow operator^(const BasicStepRow& a, const BasicStepRow& b) {
        if (a.indices[0] < b.indices[0]) { return BasicStepRow(a) ^= b; }
        else { return BasicStepRow(b) ^= a; }
    }
    friend inline bool operator==(const BasicStepRow& a, const BasicStepRow& b) { return memcmp(a.hash, b.hash, a.len) == 0; }
    friend inline bool operator<(const BasicStepRow& a, const BasicStepRow& b) { return memcmp(a.hash, b.hash, a.len) < 0; }

    friend inline bool DistinctIndices(const BasicStepRow& a, const BasicStepRow& b) { return DistinctIndices(a.indices, b.indices); }
};

class TruncatedStepRow : public StepRow
{
private:
    std::vector<eh_trunc> indices;

public:
    TruncatedStepRow(unsigned int n, const eh_HashState& base_state, eh_index i, unsigned int ilen);
    ~TruncatedStepRow() { }

    TruncatedStepRow(const TruncatedStepRow& a);
    TruncatedStepRow& operator=(const TruncatedStepRow& a);
    TruncatedStepRow& operator^=(const TruncatedStepRow& a);

    bool IndicesBefore(const TruncatedStepRow& a) { return indices[0] < a.indices[0]; }
    std::vector<eh_trunc> GetPartialSolution() { return std::vector<eh_trunc>(indices); }
    std::string GetHex() { return HexStr(hash, hash+len); }

    friend inline const TruncatedStepRow operator^(const TruncatedStepRow& a, const TruncatedStepRow& b) {
        if (a.indices[0] < b.indices[0]) { return TruncatedStepRow(a) ^= b; }
        else { return TruncatedStepRow(b) ^= a; }
    }
    friend inline bool operator==(const TruncatedStepRow& a, const TruncatedStepRow& b) { return memcmp(a.hash, b.hash, a.len) == 0; }
    friend inline bool operator<(const TruncatedStepRow& a, const TruncatedStepRow& b) { return memcmp(a.hash, b.hash, a.len) < 0; }
    friend inline bool DistinctIndices(const TruncatedStepRow& a, const TruncatedStepRow& b) { return DistinctIndices(a.indices, b.indices); }
};

class Equihash
{
private:
    unsigned int n;
    unsigned int k;

public:
    Equihash(unsigned int n, unsigned int k);

    inline unsigned int CollisionBitLength() { return n/(k+1); }
    inline unsigned int CollisionByteLength() { return CollisionBitLength()/8; }

    int InitialiseState(eh_HashState& base_state);
    std::set<std::vector<eh_index>> BasicSolve(const eh_HashState& base_state);
    std::set<std::vector<eh_index>> OptimisedSolve(const eh_HashState& base_state);
    bool IsValidSolution(const eh_HashState& base_state, std::vector<eh_index> soln);
};

#endif // BITCOIN_EQUIHASH_H
