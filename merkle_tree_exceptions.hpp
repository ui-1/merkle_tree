#pragma once
#include <stdexcept>


struct MerkleTreeFullException final : std::runtime_error {
    MerkleTreeFullException() : std::runtime_error("Merkle tree is full") {}
};

struct MerkleNodeIndexOutOfRangeException final : std::runtime_error {
    MerkleNodeIndexOutOfRangeException() : std::runtime_error("Node index out of range") {}
};

struct MerkleTreeEmptyException final : std::runtime_error {
    MerkleTreeEmptyException() : std::runtime_error("Merkle tree is empty") {}
};
