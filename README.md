## Merkle Tree

A fixed-size (32 nodes, 5 levels) Merkle tree in C++. Implemented functionality includes:
- Adding hashes to the tree
- Calculating the root hash
- Generating proofs for leaf nodes containing data hashes
- Verifying generated proofs independently of the tree


## Building and testing

[Catch2](https://github.com/catchorg/Catch2) (v3 branch) is used for unit testing -- most package managers (including `apt`) still have the v2 branch, so you may need to [install it manually](https://github.com/catchorg/Catch2/blob/devel/docs/cmake-integration.md#installing-catch2-from-git-repository).
The following assumes that you are running the latest version of Ubuntu and have the v3 branch of Catch2 installed:

```bash
# Install required packages
sudo apt install git cmake build-essential

# Clone and enter the project directory
git clone https://github.com/ui-1/merkle_tree.git
cd merkle_tree/

# Create and enter the build directory
mkdir build
cd build/

# Generate build files and compile the project
cmake ..
make

# Run the tests
./tests
```


## Design choices

- The task specifies the proof generation function's argument as an `std::size_t`. For consistency, I kept the same type for other indexes throughout the code. However, for such a small tree, it might be more appropriate to use a smaller type.
- If the original task hadn't specified MerkleTree to be a struct, I would have made it a class [as per the C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Rc-class).
- While it is a minor deviation from the original task, I did choose to rename some functions to be more descriptive. For example, `proof_for(std::size_t index)` was renamed to `generateProof(std::size_t leafNodeIndex)`.


## Theoretical Questions

### Security
>Do you have some arguments for whether the specification for the `MerkleTree` class is good in the context of security (assuming that it is meant to be a general purpose implementation)?

- `std::hash` is not a cryptographically secure hash function. In a real-world application, something like SHA-256 would be more appropriate.
- Because of the fixed size, an attacker with access to the tree could fill it with garbage data so that legitimate data could no longer be added.
- The root hash does not indicate the height of the tree, making a second-preimage attack possible (an attacker could create a different tree that has the same root hash).


### Multithreading
>What synchronization primitives would be required to allow the use of `MerkleTree` in a multithreaded programm, i.e. where multiple threads call `add_hash_of`, `root_hash` and/or `proof_for` on the same `MerkleTree` instance (object)? Or any ideas for a higher-level way how to synchronise access to a `MerkleTree` object?

Use a reader-writer pattern in which multiple threads can read the tree at the same time, but only one thread can write to it. This would allow for multiple threads to call `getRootHash` and `generateProof` (reading) simultaneously while restricting calls of  `addHashOf` (writing) to one thread. The implementation could use `std::shared_mutex`.

### Scaling
>Do you have some thoughts about what to keep in mind when scaling the `MerkleTree` class to larger and larger sizes? Is that even realistically possible?

- For a fixed size, I currently used `std::array` as the total capacity is known at the time of compiling. To be able to scale the tree, a dynamic structure such as `std::vector` would be more appropriate.
- Since this fixed-size implementation is limited to only 32 nodes, I did not implement any kind of lazy computation -- hashes of intermediate nodes are computed from scratch every single time. For a larger tree, it would be more efficient to *store* the hashes of the nodes and only recompute those hashes that change after an operation.
- Computing the root hash for the first time (or at all, if the intermediary hashes are not stored) can be really expensive for large trees. This calculation could be easily parallelized -- for example, you could have four threads calculating the hashes of four different branches of the tree (the four grandchildren of the root node) whose results are then combined to find the root hash.
- While more of a usability issue, this implementation does not allow for removing, replacing or querying hashes once they have been added.
