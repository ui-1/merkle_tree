#define CATCH_CONFIG_MAIN
#include <set>
#include "catch2/catch_test_macros.hpp"
#include "merkle_tree.hpp"
#include "merkle_tree_exceptions.hpp"


TEST_CASE("MerkleTree", "[merkle_tree]") {
    MerkleTree tree;

    SECTION("Adding 33rd node throws exception") {
        for (int i = 0; i < treeCapacity; i++) {
            tree.addHashOf("data");
        }

        REQUIRE_THROWS_AS(tree.addHashOf("33rd data node"), MerkleTreeFullException);
    }

    SECTION("Taking root hash of empty tree throws exception") {
        REQUIRE_THROWS_AS(tree.getRootHash(), MerkleTreeEmptyException);
    }

    SECTION("Adding a node updates root hash") {
        std::array<hash_t, treeCapacity> rootHashes {};
        for (int i = 1; i <= treeCapacity; i++) {
            tree.addHashOf("data " + std::to_string(i));
            rootHashes[i-1] = tree.getRootHash();
        }

        /**
         * Require all the root hashes to be unique
         */
        std::set uniqueRootHashes(rootHashes.begin(), rootHashes.end());
        REQUIRE(uniqueRootHashes.size() == rootHashes.size());
    }

    SECTION("Proof generation for out of range index throws exception") {
        for (int i = 0; i < treeCapacity; i++) {
            tree.addHashOf("data");
        }

        REQUIRE_THROWS_AS(tree.generateProof(treeCapacity), MerkleNodeIndexOutOfRangeException);
    }

    SECTION("Proof generation for empty tree throws exception") {
        REQUIRE_THROWS_AS(tree.generateProof(0), MerkleTreeEmptyException);
    }

    SECTION("Valid proof returns true") {
        tree.addHashOf("data1");
        tree.addHashOf("data2");
        tree.addHashOf("data3");

        hash_t rootHash = tree.getRootHash();
        proof_t proof = tree.generateProof(1);

        REQUIRE(verifyProof(rootHash, proof, "data2") == true);
    }

    SECTION("Invalid proof returns false") {
        tree.addHashOf("data1");
        tree.addHashOf("data2");
        tree.addHashOf("data3");

        hash_t rootHash = tree.getRootHash();
        proof_t proof = tree.generateProof(1);

        REQUIRE(verifyProof(rootHash, proof, "fake data") == false);
    }

    SECTION("Correct proof becomes invalid after adding new data") {
        tree.addHashOf("data1");
        tree.addHashOf("data2");
        tree.addHashOf("data3");

        hash_t rootHash = tree.getRootHash();
        proof_t proof = tree.generateProof(1);

        REQUIRE(verifyProof(rootHash, proof, "data2") == true);

        tree.addHashOf("data4");
        rootHash = tree.getRootHash();

        REQUIRE(verifyProof(rootHash, proof, "data2") == false);
    }

    SECTION("Generate and verify proof for each node in a tree with {1, 2, ..., 32} nodes") {
        for (int numberOfNodes = 1; numberOfNodes <= treeCapacity; numberOfNodes++) {
            tree = MerkleTree();
            std::vector<std::string> dataValues(numberOfNodes);

            for (int i = 0; i < numberOfNodes; i++) {
                dataValues.at(i) = "data " + std::to_string(i + 1);
                tree.addHashOf(dataValues.at(i));
            }

            hash_t rootHash = tree.getRootHash();

            for (int i = 0; i < numberOfNodes; i++) {
                proof_t proof = tree.generateProof(i);
                REQUIRE(verifyProof(rootHash, proof, dataValues.at(i)) == true);
            }
        }
    }
}
