// Copyright (c) 2016 Jack Grigg
// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Implementation of the Equihash Proof-of-Work algorithm.
//
// Reference
// =========
// Alex Biryukov and Dmitry Khovratovich
// Equihash: Asymmetric Proof-of-Work Based on the Generalized Birthday Problem
// NDSS ’16, 21-24 February 2016, San Diego, CA, USA
// https://www.internetsociety.org/sites/default/files/blogs-media/equihash-asymmetric-proof-of-work-based-generalized-birthday-problem.pdf

#include "crypto/equihash.h"
#include "util.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>

void validate_params(int n, int k)
{
    if (k>=n) {
        std::cerr << "n must be larger than k\n";
        throw invalid_params();
    }
    if (n % 8 != 0) {
        std::cerr << "Parameters must satisfy n = 0 mod 8\n";
        throw invalid_params();
    }
    if ((n/(k+1)) % 8 != 0) {
        std::cerr << "Parameters must satisfy n/(k+1) = 0 mod 8\n";
        throw invalid_params();
    }
}

int Equihash::InitialiseState(eh_HashState& base_state)
{
    unsigned char personalization[crypto_generichash_blake2b_PERSONALBYTES] = {};
    memcpy(personalization, "ZcashPOW", 8);
    memcpy(personalization+8,  &n, 4);
    memcpy(personalization+12, &k, 4);
    return crypto_generichash_blake2b_init_salt_personal(&base_state,
                                                         NULL, 0, // No key.
                                                         n/8,
                                                         NULL,    // No salt.
                                                         personalization);
}

StepRow::StepRow(unsigned int n, const eh_HashState& base_state, eh_index i) :
        hash {new unsigned char[n/8]},
        len {n/8}
{
    eh_HashState state;
    state = base_state;
    crypto_generichash_blake2b_update(&state, (unsigned char*) &i, sizeof(eh_index));
    crypto_generichash_blake2b_final(&state, hash, n/8);
}

StepRow::~StepRow()
{
    delete[] hash;
}

StepRow::StepRow(const StepRow& a) :
        hash {new unsigned char[a.len]},
        len {a.len}
{
    for (int i = 0; i < len; i++)
        hash[i] = a.hash[i];
}

BasicStepRow::BasicStepRow(unsigned int n, const eh_HashState& base_state, eh_index i) :
        StepRow {n, base_state, i},
        indices {i}
{
    assert(indices.size() == 1);
}

BasicStepRow::BasicStepRow(const BasicStepRow& a) :
        StepRow {a},
        indices(a.indices)
{
}

BasicStepRow& BasicStepRow::operator=(const BasicStepRow& a)
{
    unsigned char* p = new unsigned char[a.len];
    for (int i = 0; i < a.len; i++)
        p[i] = a.hash[i];
    delete[] hash;
    hash = p;
    len = a.len;
    indices = a.indices;
    return *this;
}

BasicStepRow& BasicStepRow::operator^=(const BasicStepRow& a)
{
    if (a.len != len) {
        throw std::invalid_argument("Hash length differs");
    }
    if (a.indices.size() != indices.size()) {
        throw std::invalid_argument("Number of indices differs");
    }
    unsigned char* p = new unsigned char[len];
    for (int i = 0; i < len; i++)
        p[i] = hash[i] ^ a.hash[i];
    delete[] hash;
    hash = p;
    indices.reserve(indices.size() + a.indices.size());
    indices.insert(indices.end(), a.indices.begin(), a.indices.end());
    return *this;
}

void StepRow::TrimHash(int l)
{
    unsigned char* p = new unsigned char[len-l];
    for (int i = 0; i < len-l; i++)
        p[i] = hash[i+l];
    delete[] hash;
    hash = p;
    len -= l;
}

bool StepRow::IsZero()
{
    char res = 0;
    for (int i = 0; i < len; i++)
        res |= hash[i];
    return res == 0;
}

bool HasCollision(StepRow& a, StepRow& b, int l)
{
    bool res = true;
    for (int j = 0; j < l; j++)
        res &= a.hash[j] == b.hash[j];
    return res;
}

// Checks if the intersection of a.indices and b.indices is empty
template<typename INDEX_TYPE>
bool DistinctIndices(const std::vector<INDEX_TYPE>& a, const std::vector<INDEX_TYPE>& b)
{
    std::vector<INDEX_TYPE> aSrt(a);
    std::vector<INDEX_TYPE> bSrt(b);

    std::sort(aSrt.begin(), aSrt.end());
    std::sort(bSrt.begin(), bSrt.end());

    unsigned int i = 0;
    for (unsigned int j = 0; j < bSrt.size(); j++) {
        while (aSrt[i] < bSrt[j]) {
            i++;
            if (i == aSrt.size()) { return true; }
        }
        assert(aSrt[i] >= bSrt[j]);
        if (aSrt[i] == bSrt[j]) { return false; }
    }
    return true;
}

Equihash::Equihash(unsigned int n, unsigned int k) :
        n(n), k(k)
{
    validate_params(n, k);
}

std::set<std::vector<eh_index>> Equihash::BasicSolve(const eh_HashState& base_state)
{
    assert(CollisionBitLength() + 1 < 8*sizeof(eh_index));
    eh_index init_size { ((eh_index) 1) << (CollisionBitLength() + 1) };

    // 1) Generate first list
    LogPrint("pow", "Generating first list\n");
    std::vector<BasicStepRow> X;
    X.reserve(init_size);
    for (eh_index i = 0; i < init_size; i++) {
        X.emplace_back(n, base_state, i);
    }

    // 3) Repeat step 2 until 2n/(k+1) bits remain
    for (int r = 1; r < k && X.size() > 0; r++) {
        LogPrint("pow", "Round %d:\n", r);
        // 2a) Sort the list
        LogPrint("pow", "- Sorting list\n");
        std::sort(X.begin(), X.end());

        LogPrint("pow", "- Finding collisions\n");
        int i = 0;
        int posFree = 0;
        std::vector<BasicStepRow> Xc;
        while (i < X.size() - 1) {
            // 2b) Find next set of unordered pairs with collisions on the next n/(k+1) bits
            int j = 1;
            while (i+j < X.size() &&
                    HasCollision(X[i], X[i+j], CollisionByteLength())) {
                j++;
            }

            // 2c) Calculate tuples (X_i ^ X_j, (i, j))
            for (int l = 0; l < j - 1; l++) {
                for (int m = l + 1; m < j; m++) {
                    if (DistinctIndices(X[i+l], X[i+m])) {
                        Xc.push_back(X[i+l] ^ X[i+m]);
                        Xc.back().TrimHash(CollisionByteLength());
                    }
                }
            }

            // 2d) Store tuples on the table in-place if possible
            while (posFree < i+j && Xc.size() > 0) {
                X[posFree++] = Xc.back();
                Xc.pop_back();
            }

            i += j;
        }

        // 2e) Handle edge case where final table entry has no collision
        while (posFree < X.size() && Xc.size() > 0) {
            X[posFree++] = Xc.back();
            Xc.pop_back();
        }

        if (Xc.size() > 0) {
            // 2f) Add overflow to end of table
            X.insert(X.end(), Xc.begin(), Xc.end());
        } else if (posFree < X.size()) {
            // 2g) Remove empty space at the end
            X.erase(X.begin()+posFree, X.end());
            X.shrink_to_fit();
        }
    }

    // k+1) Find a collision on last 2n(k+1) bits
    LogPrint("pow", "Final round:\n");
    std::set<std::vector<eh_index>> solns;
    if (X.size() > 1) {
        LogPrint("pow", "- Sorting list\n");
        std::sort(X.begin(), X.end());
        LogPrint("pow", "- Finding collisions\n");
        for (int i = 0; i < X.size() - 1; i++) {
            BasicStepRow res = X[i] ^ X[i+1];
            if (res.IsZero() && DistinctIndices(X[i], X[i+1])) {
                solns.insert(res.GetSolution());
            }
        }
    } else
        LogPrint("pow", "- List is empty\n");

    return solns;
}

bool Equihash::IsValidSolution(const eh_HashState& base_state, std::vector<eh_index> soln)
{
    eh_index soln_size { pow(2, k) };
    if (soln.size() != soln_size) {
        LogPrint("pow", "Invalid solution size: %d\n", soln.size());
        return false;
    }

    std::vector<BasicStepRow> X;
    X.reserve(soln_size);
    for (eh_index i : soln) {
        X.emplace_back(n, base_state, i);
    }

    while (X.size() > 1) {
        std::vector<BasicStepRow> Xc;
        for (int i = 0; i < X.size(); i += 2) {
            if (!HasCollision(X[i], X[i+1], CollisionByteLength())) {
                LogPrint("pow", "Invalid solution: invalid collision length between StepRows\n");
                LogPrint("pow", "X[i]   = %s\n", X[i].GetHex());
                LogPrint("pow", "X[i+1] = %s\n", X[i+1].GetHex());
                return false;
            }
            if (X[i+1].IndicesBefore(X[i])) {
                return false;
                LogPrint("pow", "Invalid solution: Index tree incorrectly ordered\n");
            }
            if (!DistinctIndices(X[i], X[i+1])) {
                LogPrint("pow", "Invalid solution: duplicate indices\n");
                return false;
            }
            Xc.push_back(X[i] ^ X[i+1]);
            Xc.back().TrimHash(CollisionByteLength());
        }
        X = Xc;
    }

    assert(X.size() == 1);
    return X[0].IsZero();
}


//
// OPTIMISATIONS BELOW HERE
//


TruncatedStepRow::TruncatedStepRow(unsigned int n, const eh_HashState& base_state, eh_index i, unsigned int ilen) :
        StepRow {n, base_state, i}
{
    // Truncate to 8 bits
    assert(sizeof(eh_trunc) == 1);
    eh_trunc itrunc { (i >> (ilen - 8)) & 0xff };

    indices.reserve(1);
    indices.push_back(itrunc);
    full_indices.reserve(1);
    full_indices.push_back(i);

    assert(indices.size() == 1);
    assert(full_indices.size() == 1);
}

TruncatedStepRow::TruncatedStepRow(const TruncatedStepRow& a) :
        StepRow {a},
        indices(a.indices),
        full_indices(a.full_indices)
{
}

TruncatedStepRow& TruncatedStepRow::operator=(const TruncatedStepRow& a)
{
    unsigned char* p = new unsigned char[a.len];
    for (int i = 0; i < a.len; i++)
        p[i] = a.hash[i];
    delete[] hash;
    hash = p;
    len = a.len;
    indices = a.indices;
    full_indices = a.full_indices;
    return *this;
}

TruncatedStepRow& TruncatedStepRow::operator^=(const TruncatedStepRow& a)
{
    if (a.len != len) {
        throw std::invalid_argument("Hash length differs");
    }
    if (a.indices.size() != indices.size()) {
        throw std::invalid_argument("Number of indices differs");
    }
    unsigned char* p = new unsigned char[len];
    for (int i = 0; i < len; i++)
        p[i] = hash[i] ^ a.hash[i];
    delete[] hash;
    hash = p;
    indices.reserve(indices.size() + a.indices.size());
    indices.insert(indices.end(), a.indices.begin(), a.indices.end());
    full_indices.reserve(full_indices.size() + a.full_indices.size());
    full_indices.insert(full_indices.end(), a.full_indices.begin(), a.full_indices.end());
    return *this;
}

std::set<std::vector<eh_index>> Equihash::OptimisedSolve(const eh_HashState& base_state)
{
    assert(CollisionBitLength() + 1 < 8*sizeof(eh_index));
    eh_index init_size { ((eh_index) 1) << (CollisionBitLength() + 1) };

    // First run the algorithm with truncated indices

    // 1) Generate first list
    LogPrint("pow", "Generating first list\n");
    std::vector<TruncatedStepRow> Xt;
    Xt.reserve(init_size);
    for (eh_index i = 0; i < init_size; i++) {
        Xt.emplace_back(n, base_state, i, CollisionBitLength() + 1);
    }

    // 3) Repeat step 2 until 2n/(k+1) bits remain
    for (int r = 1; r < k && Xt.size() > 0; r++) {
        LogPrint("pow", "Round %d:\n", r);
        // 2a) Sort the list
        LogPrint("pow", "- Sorting list\n");
        std::sort(Xt.begin(), Xt.end());

        LogPrint("pow", "- Finding collisions\n");
        int i = 0;
        int posFree = 0;
        std::vector<TruncatedStepRow> Xc;
        while (i < Xt.size() - 1) {
            // 2b) Find next set of unordered pairs with collisions on the next n/(k+1) bits
            int j = 1;
            while (i+j < Xt.size() &&
                    HasCollision(Xt[i], Xt[i+j], CollisionByteLength())) {
                j++;
            }

            // 2c) Calculate tuples (X_i ^ X_j, (i, j))
            for (int l = 0; l < j - 1; l++) {
                for (int m = l + 1; m < j; m++) {
                    // We truncated, so don't check for distinct indices here
                    Xc.push_back(Xt[i+l] ^ Xt[i+m]);
                    Xc.back().TrimHash(CollisionByteLength());
                }
            }

            // 2d) Store tuples on the table in-place if possible
            while (posFree < i+j && Xc.size() > 0) {
                Xt[posFree++] = Xc.back();
                Xc.pop_back();
            }

            i += j;
        }

        // 2e) Handle edge case where final table entry has no collision
        while (posFree < Xt.size() && Xc.size() > 0) {
            Xt[posFree++] = Xc.back();
            Xc.pop_back();
        }

        if (Xc.size() > 0) {
            // 2f) Add overflow to end of table
            Xt.insert(Xt.end(), Xc.begin(), Xc.end());
        } else if (posFree < Xt.size()) {
            // 2g) Remove empty space at the end
            Xt.erase(Xt.begin()+posFree, Xt.end());
            Xt.shrink_to_fit();
        }
    }

    // k+1) Find a collision on last 2n(k+1) bits
    LogPrint("pow", "Final round:\n");
    std::set<std::vector<eh_trunc>> partialSolns;
    if (Xt.size() > 1) {
        LogPrint("pow", "- Sorting list\n");
        std::sort(Xt.begin(), Xt.end());
        LogPrint("pow", "- Finding collisions\n");
        for (int i = 0; i < Xt.size() - 1; i++) {
            TruncatedStepRow res = Xt[i] ^ Xt[i+1];
            if (res.IsZero() && DistinctIndices(Xt[i], Xt[i+1])) {
                partialSolns.insert(res.GetPartialSolution());
            }
        }
    } else
        LogPrint("pow", "- List is empty\n");

    LogPrint("pow", "Found %d partial solutions\n", partialSolns.size());

    // Now for each solution run the algorithm again to recreate the indices
    std::set<std::vector<eh_index>> solns;
    eh_index recreate_size { ((eh_index) 1) << (CollisionBitLength() - 7) };

    for (std::vector<eh_trunc> partialSoln : partialSolns) {
        LogPrint("pow", "Solution: ");
        for (eh_trunc index : partialSoln) {
            LogPrint("pow", "%d,", index);
        }
        LogPrint("pow", "\n");

        // 1) Generate first list of possibilities
        LogPrint("pow", "Generating first list of possibilities\n");
        LogPrint("pow", "- partialSoln.size() = %d\n", partialSoln.size());
        std::vector<std::vector<BasicStepRow>> X;
        X.reserve(partialSoln.size());
        for (int i = 0; i < partialSoln.size(); i++) {
            std::vector<BasicStepRow> ic;
            ic.reserve(recreate_size);
            for (eh_index j = 0; j < recreate_size; j++) {
                ic.emplace_back(n, base_state, (partialSoln[i] << recreate_size) | j);
            }
            X.push_back(ic);
        }

        // 3) Repeat step 2 for each level of the tree
        while (X.size() > 1) {
            LogPrint("pow", "X.size() = %d:\n", X.size());

            // For each list:
            for (int v = 0; v < X.size(); v++) {
                LogPrint("pow", "- List %d size = %d:\n", v+1, X[v].size());
                if (X[v].size() == 0) continue;

                // 2a) Sort the list
                LogPrint("pow", "  - Sorting list\n");
                std::sort(X[v].begin(), X[v].end());
            }

            std::vector<std::vector<BasicStepRow>> Xc;
            Xc.reserve(X.size()/2);

            // For each pair of lists:
            for (int v = 0; v < X.size(); v += 2) {
                LogPrint("pow", "- Pair %d:\n", (v/2)+1);
                LogPrint("pow", "  - Finding collisions\n");
                int iChecked = 0;
                int jChecked = 0;
                std::vector<BasicStepRow> ic;
                while (iChecked < X[v].size() && jChecked < X[v+1].size()) {
                    LogPrint("pow", "    - iChecked = %d\n", iChecked);
                    LogPrint("pow", "    - jChecked = %d\n", jChecked);
                    // 2b) Find next set of unordered pairs with collisions on the next n/(k+1) bits
                    int i = 0;
                    int j = 1;
                    while (iChecked+i < X[v].size() &&
                            HasCollision(X[v][iChecked+i], X[v+1][jChecked], CollisionByteLength())) {
                        i++;
                    }
                    while (jChecked+j < X[v+1].size() &&
                            HasCollision(X[v][iChecked], X[v+1][jChecked+j], CollisionByteLength())) {
                        j++;
                    }

                    // 2c) Calculate tuples (X_i ^ X_j, (i, j))
                    for (int l = 0; l < i; l++) {
                        for (int m = 0; m < j; m++) {
                            if (DistinctIndices(X[v][iChecked+l], X[v+1][jChecked+m])) {
                                ic.push_back(X[v][iChecked+l] ^ X[v][jChecked+m]);
                                ic.back().TrimHash(CollisionByteLength());
                            }
                        }
                    }

                    if (i == 0 && j == 0) {
                        jChecked++;
                    } else {
                        iChecked += i;
                        jChecked += j;
                    }
                }

                Xc.push_back(ic);
            }

            X = Xc;
        }

        // We are at the top of the tree
        assert(X.size() == 1);
        LogPrint("pow", "Number of possibilities: %d\n", X[0].size());
        for (BasicStepRow row : X[0]) {
            solns.insert(row.GetSolution());
        }
    }

    return solns;
}
