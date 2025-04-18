#include <algorithm>
#include <string>
#include "merkle_tree.hpp"
#include "merkle_tree_exceptions.hpp"


MerkleTree::MerkleNode MerkleTree::MerkleNode::getSiblingNode() const noexcept {
    /**
     * The sibling node that we're looking for is on the same level as this node (as it has the same parent).
     *
     * Two siblings have indexes 0 and 1, 2 and 3, 4 and 5, etc. If this node has the even index out of the two,
     * then its sibling must have the odd index which is greater by 1. This means 0 -> 1, 2 -> 3, 4 -> 5, etc.
     *
     * If this node has the odd index out of the two, then its sibling must have the even index which is smaller by 1.
     * This means 1 -> 0, 3 -> 2, 5 -> 4, etc.
     */

    if (index % 2 == 0) {
        return {level, index + 1};
    }

    return {level, index - 1};
}

std::array<MerkleTree::MerkleNode, treeHeight> MerkleTree::MerkleNode::getPathFromLeafToRoot() const noexcept {
    std::array<MerkleNode, treeHeight> path = {};
    std::size_t pathNodeIndex = index;

    /**
     * The path from the leaf node to the root node is constructed by going up the tree. We start with the the leaf node
     * (i.e. at the bottom of the tree) and, in order to find the index of the parent node one level above,
     * floor divide the current index by 2. This way, 0 and 1 map to 0 (first node on the level directly above),
     * 2 and 3 map to 1 (second node), etc.
     */
    for (std::size_t pathNodeLevel = treeHeight; pathNodeLevel > 0; pathNodeLevel--) {
        const auto pathNode = MerkleNode(pathNodeLevel, pathNodeIndex);

        path[treeHeight - pathNodeLevel] = pathNode;
        pathNodeIndex /= 2;
    }

    return path;
}

hash_t MerkleTree::getNodeHash(const MerkleNode &node) const noexcept {
    if (node.isLeaf()) {
        return treeLeafNodes[node.getIndex()];
    }

    const hash_t leftChildHash = getNodeHash(node.getLeftChild());
    const hash_t rightChildHash = getNodeHash(node.getRightChild());

    return std::hash<hash_t>()(leftChildHash + rightChildHash);
}

void MerkleTree::addHashOf(const std::string &data) {
    if (isFull()) {
        throw MerkleTreeFullException();
    }

    const hash_t dataHash = std::hash<std::string>()(data);
    treeLeafNodes[currentTreeSize] = dataHash;
    currentTreeSize++;

    currentRootHash = getNodeHash({0, 0});
}

hash_t MerkleTree::getRootHash() const {
    if (isEmpty()) {
        throw MerkleTreeEmptyException();
    }

    return currentRootHash;
}

proof_t MerkleTree::generateProof(const std::size_t leafNodeIndex) const {
    if (isEmpty()) {
        throw MerkleTreeEmptyException();
    }

    if (leafNodeIndex >= currentTreeSize) {
        throw MerkleNodeIndexOutOfRangeException();
    }

    const MerkleNode leafNode = {treeHeight, leafNodeIndex};
    const std::array<MerkleNode, treeHeight> pathFromLeafToRoot = leafNode.getPathFromLeafToRoot();

    /**
     * For each node in the path from leaf to root, find the hash of its sibling -- these hashes together constitute the proof.
     * See the implementation of `verifyProof` for details on how the proof is used.
     */
    std::array<hash_t, treeHeight> siblingHashes = {};
    for (std::size_t i = 0; i < pathFromLeafToRoot.size(); i++) {
        siblingHashes[i] = getNodeHash(pathFromLeafToRoot[i].getSiblingNode());
    }

    return siblingHashes;
}

bool verifyProof(const hash_t &rootHash, const proof_t &proof, const std::string &data) noexcept {
    /**
     * The proof consists of the hashes of the sibling nodes on the path from the leaf node to the root node. In order
     * to see if the data was in the tree with the given root hash, we need to calculate the hash of the root node
     * based on the given data node and the given proof.
     *
     * The hash of the data node combined with the first hash of the proof (which is the hash of the data node's sibling)
     * is the hash of their parent node. This parent node is then combined with the next proof hash (the hash of the
     * sibling of the data node's parent) and so on, until we reach the root node and its hash.
     */

    hash_t computedHash = std::hash<std::string>()(data);

    for (const hash_t proofHash : proof) {
        computedHash = std::hash<hash_t>()(computedHash + proofHash);
    }

    return computedHash == rootHash;
}
