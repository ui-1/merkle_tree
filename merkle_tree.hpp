#pragma once
#include <array>


/**
 * The height of the tree
 */
static constexpr int treeHeight = 5;

/**
 * Capacity doubles with each level, so the total capacity of the tree is 2^TREE_HEIGHT.
 *
 * To get 2^TREE_HEIGHT, shift the binary representation of the decimal value 1 to the left by TREE_HEIGHT bits.
 * For example, if TREE_HEIGHT is 5, then 00000001 << 5 = 00100000 = 32.
 */
static constexpr int treeCapacity = 1 << treeHeight;

using hash_t = std::size_t;
using proof_t = std::array<hash_t, treeHeight>;

struct MerkleTree {

private:

    /**
     * Struct representing the location of a single node in a Merkle tree by its level and index. Used for finding
     * the node's children, finding sibling nodes and calculating the path from this node to the root node.
     *
     * Note: MerkleNode is meant to be used only by MerkleTree and does not perform any sort of input validation
     * (for example, that getSiblingNode() would not be called on a root node). Correct usage of its methods is to
     * be guaranteed by the MerkleTree class.
     */
    struct MerkleNode {
        /**
         * Level of the node. The root node is on level 0, its children are on level 1, etc.
         */
        std::size_t level;

        /**
         * Index of the node. The leftmost node of a level is at index 0, the next one is at index 1, etc.
         */
        std::size_t index;

        MerkleNode(const std::size_t level, const std::size_t index) : level(level), index(index) {}
        MerkleNode() : level(0), index(0) {}

        [[nodiscard]] std::size_t getIndex() const noexcept {
            return index;
        }

        /**
         * @return true if this struct represents a leaf node (is on the last level of the tree and does not have
         * any children), false otherwise.
         */
        [[nodiscard]] bool isLeaf() const noexcept {
            return level == treeHeight;
        }

        /**
         * @return the sibling node, i.e. the node that is on the same level and has the same parent.
         */
        [[nodiscard]] MerkleNode getSiblingNode() const noexcept;

        /**
         * Find the path from this (leaf) node to the root node of the tree.
         * @return std::array of MerkleNode structs [n_1, n_2, ..., n_k] (k = TREE_HEIGHT) where n_1 is this node and
         * n_2 is its parent, n_3 is the parent of n_2, etc. The last node of the array, n_k, is a child of the root node.
         */
        [[nodiscard]] std::array<MerkleNode, treeHeight> getPathFromLeafToRoot() const noexcept;

        /**
         * @return the left child of this node, i.e. the node that is one level below this node and, out of the
         * indexes of this node's children (2 * index and 2 * index + 1), has the former.
         */
        [[nodiscard]] MerkleNode getLeftChild() const noexcept {
            return {level + 1, 2 * index};
        }

        /**
         * @return the right child of this node, i.e. the node that is one level below this node and, out of the
         * indexes of this node's children (2 * index and 2 * index + 1), has the latter.
         */
        [[nodiscard]] MerkleNode getRightChild() const noexcept {
            return {level + 1, 2 * index + 1};
        }
    };

    /**
     * Calculate the hash of a given node. The hash of a leaf node is the hash of the data that was inserted into it
     * and the hash of a non-leaf node is the hash of the sum of its children's hashes, found recursively.
     *
     * @return hash of the given node
     */
    [[nodiscard]] hash_t getNodeHash(const MerkleNode &node) const noexcept;

    /**
     * @return true if the tree is full, false otherwise.
     */
    [[nodiscard]] bool isFull() const noexcept {
        return currentTreeSize == treeCapacity;
    }

    /**
     * @return true if the tree is empty, false otherwise.
     */
    [[nodiscard]] bool isEmpty() const noexcept {
        return currentTreeSize == 0;
    }

    /**
     * The initial root hash is overwritten as soon as the first data node is inserted. Before this, trying to query
     * the root hash will throw an exception (see getRootHash), so this value will never be seen by the user of the tree.
     */
    hash_t currentRootHash = 0;

    std::size_t currentTreeSize = 0;

    /**
     * For the leaf nodes, an initial value of 0 is used as a placeholder. This is something that won't be visible
     * from the outside and should not concern the user of the tree.
     *
     * The placeholder value works since a parent node's hash is calculated as a hash of the sum of its children's
     * hashes and thus a child's hash of 0 will not affect the parent's hash until it is replaced with a real value.
     *
     * For example, if the right child of a node is empty (has a hash of 0) and the left child has a real value,
     * the hash of the parent node will be H(left_child + 0) = H(left_child) i.e. the hash depends only on the one
     * child that does have a real, non-zero value.
     *
     * It is technically possible for a collision to occur (i.e. some newly inserted data could get a hash of 0) but,
     * in order to abuse this, an attacker would need to find a preimage for a specific value which is considered to be
     * infeasible for most hash functions (more so for cryptographic hashes, if one was to be used instead of std::hash).
     */
    std::array<hash_t, treeCapacity> treeLeafNodes = {};


public:

    /**
     * The tree has a capacity of 2^TREE_HEIGHT elements and is empty upon creation. Note that this Merkle tree does
     * not store the original data in its leaf nodes, only the hashes of the data.
     */
    MerkleTree() = default;

    /**
     * Insert a data hash into the tree, 0-indexed: the first added hash is at index 0, the second at index 1, etc.
     * @throws MerkleTreeFullException if the tree is full
     */
    void addHashOf(const std::string &data);

    /**
     * Get the root hash of the tree. The value changes (modulo hash collisions) whenever new hashes are inserted.
     * @throws MerkleTreeEmptyException if the tree is empty
     */
    [[nodiscard]] hash_t getRootHash() const;

    /**
     * Generate a proof for a given index (0-indexed, described in `addHashOf`), to be used in the `verifyProof` function.
     * The proof produced is completely independent of the tree in that it can be verified even without knowing anything
     * about the tree other than the root node.
     *
     * @return proof_t containing the hashes of the sibling nodes on the path from the leaf node to the root node.
     * @throws MerkleNodeIndexOutOfRangeException if the index is out of range (greater than or equal to TREE_CAPACITY)
     * @throws MerkleTreeEmptyException if the tree is empty
     */
    [[nodiscard]] proof_t generateProof(std::size_t leafNodeIndex) const;
};


/**
 * Verify whether the given data was in the tree with the given root hash.
 * @param rootHash the hash of the root node of the tree
 * @param proof the proof generated by `generateProof`
 * @param data the data whose presence in the tree is to be verified
 * @return true if the data was in the tree, false otherwise
 */
[[nodiscard]] bool verifyProof(const hash_t &rootHash, const proof_t &proof, const std::string &data) noexcept;
