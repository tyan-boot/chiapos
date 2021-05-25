#include "prover_disk.hpp"

DiskProver::DiskProver(const std::string& filename)
{
    struct plot_header header{};
    this->filename = filename;

    std::ifstream disk_file(filename, std::ios::in | std::ios::binary);

    if (!disk_file.is_open()) {
        throw std::invalid_argument("Invalid file " + filename);
    }
    // 19 bytes  - "Proof of Space Plot" (utf-8)
    // 32 bytes  - unique plot id
    // 1 byte    - k
    // 2 bytes   - format description length
    // x bytes   - format description
    // 2 bytes   - memo length
    // x bytes   - memo

    SafeRead(disk_file, (uint8_t*)&header, sizeof(header));
    if (memcmp(header.magic, "Proof of Space Plot", sizeof(header.magic)) != 0)
        throw std::invalid_argument("Invalid plot header magic");

    uint16_t fmt_desc_len = Util::TwoBytesToInt(header.fmt_desc_len);

    if (fmt_desc_len == kFormatDescription.size() &&
        !memcmp(header.fmt_desc, kFormatDescription.c_str(), fmt_desc_len)) {
        // OK
    } else {
        throw std::invalid_argument("Invalid plot file format");
    }

    memcpy(this->id, header.id, sizeof(header.id));
    this->k = header.k;
    SafeSeek(disk_file, offsetof(struct plot_header, fmt_desc) + fmt_desc_len);

    uint8_t size_buf[2];
    SafeRead(disk_file, size_buf, 2);
    this->memo_size = Util::TwoBytesToInt(size_buf);
    this->memo = new uint8_t[this->memo_size];
    SafeRead(disk_file, this->memo, this->memo_size);

    this->table_begin_pointers = std::vector<uint64_t>(11, 0);
    this->C2 = std::vector<uint64_t>();

    uint8_t pointer_buf[8];
    for (uint8_t i = 1; i < 11; i++) {
        SafeRead(disk_file, pointer_buf, 8);
        this->table_begin_pointers[i] = Util::EightBytesToInt(pointer_buf);
    }

    SafeSeek(disk_file, table_begin_pointers[9]);

    uint8_t c2_size = (Util::ByteAlign(k) / 8);
    uint32_t c2_entries = (table_begin_pointers[10] - table_begin_pointers[9]) / c2_size;
    if (c2_entries == 0 || c2_entries == 1) {
        throw std::invalid_argument("Invalid C2 table size");
    }

    // The list of C2 entries is small enough to keep in memory. When proving, we can
    // read from disk the C1 and C3 entries.
    auto* c2_buf = new uint8_t[c2_size];
    for (uint32_t i = 0; i < c2_entries - 1; i++) {
        SafeRead(disk_file, c2_buf, c2_size);
        this->C2.push_back(Bits(c2_buf, c2_size, c2_size * 8).Slice(0, k).GetValue());
    }

    this->file = fopen(filename.c_str(), "r");
    this->fd = fileno(this->file);

    delete[] c2_buf;
}

DiskProver::~DiskProver()
{
    std::lock_guard<std::mutex> l(_mtx);
    delete[] this->memo;
    for (int i = 0; i < 6; i++) {
        Encoding::ANSFree(kRValues[i]);
    }
    Encoding::ANSFree(kC3R);

    fclose(this->file);
}

void DiskProver::GetId(uint8_t* buffer) { memcpy(buffer, id, kIdLen); }

std::vector<LargeBits> DiskProver::GetQualitiesForChallenge(const uint8_t* challenge)
{
    std::vector<LargeBits> qualities;

    std::lock_guard<std::mutex> l(_mtx);

    {
        std::ifstream disk_file(filename, std::ios::in | std::ios::binary);

        if (!disk_file.is_open()) {
            throw std::invalid_argument("Invalid file " + filename);
        }

        // This tells us how many f7 outputs (and therefore proofs) we have for this
        // challenge. The expected value is one proof.
        std::vector<uint64_t> p7_entries = GetP7Entries(disk_file, challenge);

        if (p7_entries.empty()) {
            return std::vector<LargeBits>();
        }

        // The last 5 bits of the challenge determine which route we take to get to
        // our two x values in the leaves.
        uint8_t last_5_bits = challenge[31] & 0x1f;

        std::vector<std::future<LargeBits>> qualities_futs{};

        for (uint64_t position : p7_entries) {
//            auto f = std::async(std::launch::async, [this, &disk_file, position, last_5_bits, challenge]() mutable {
//
//            });
//            qualities_futs.emplace_back(std::move(f));

// This inner loop goes from table 6 to table 1, getting the two backpointers,
            // and following one of them.
            for (uint8_t table_index = 6; table_index > 1; table_index--) {
                uint128_t line_point = ReadLinePoint(disk_file, table_index, position);

                auto xy = Encoding::LinePointToSquare(line_point);
                assert(xy.first >= xy.second);

                if (((last_5_bits >> (table_index - 2)) & 1) == 0) {
                    position = xy.second;
                } else {
                    position = xy.first;
                }
            }
            uint128_t new_line_point = ReadLinePoint(disk_file, 1, position);
            auto x1x2 = Encoding::LinePointToSquare(new_line_point);

            // The final two x values (which are stored in the same location) are hashed
            std::vector<unsigned char> hash_input(32 + Util::ByteAlign(2 * k) / 8, 0);
            memcpy(hash_input.data(), challenge, 32);
            (LargeBits(x1x2.second, k) + LargeBits(x1x2.first, k))
                    .ToBytes(hash_input.data() + 32);
            std::vector<unsigned char> hash(picosha2::k_digest_size);
            picosha2::hash256(hash_input.begin(), hash_input.end(), hash.begin(), hash.end());
//            return LargeBits(hash.data(), 32, 256);
            qualities.emplace_back(hash.data(), 32, 256);
        }

//        for (auto &f: qualities_futs) {
//            qualities.emplace_back(f.get());
//        }
    }  // Scope for disk_file
    return qualities;
}

LargeBits DiskProver::GetFullProof(const uint8_t* challenge, uint32_t index)
{
    LargeBits full_proof;

    std::lock_guard<std::mutex> l(_mtx);
    {
        std::ifstream disk_file(filename, std::ios::in | std::ios::binary);

        if (!disk_file.is_open()) {
            throw std::invalid_argument("Invalid file " + filename);
        }

        std::vector<uint64_t> p7_entries = GetP7Entries(disk_file, challenge);
        if (p7_entries.empty() || index >= p7_entries.size()) {
            throw std::logic_error("No proof of space for this challenge");
        }

        // Gets the 64 leaf x values, concatenated together into a k*64 bit string.
        std::vector<Bits> xs = GetInputs(disk_file, p7_entries[index], 6);

        // Sorts them according to proof ordering, where
        // f1(x0) m= f1(x1), f2(x0, x1) m= f2(x2, x3), etc. On disk, they are not stored in
        // proof ordering, they're stored in plot ordering, due to the sorting in the Compress
        // phase.
        std::vector<LargeBits> xs_sorted = ReorderProof(xs);
        for (const auto& x : xs_sorted) {
            full_proof += x;
        }
    }  // Scope for disk_file
    return full_proof;
}

void DiskProver::GetMemo(uint8_t* buffer) { memcpy(buffer, memo, this->memo_size); }

uint8_t DiskProver::GetSize() const noexcept { return k; }

uint32_t DiskProver::GetMemoSize() const noexcept { return this->memo_size; }

LargeBits DiskProver::GetFullProof(uint32_t index, const std::vector<uint64_t>& p7_entries) {
    LargeBits full_proof;

    std::lock_guard<std::mutex> l(_mtx);
    {
        std::ifstream disk_file(filename, std::ios::in | std::ios::binary);

        if (!disk_file.is_open()) {
            throw std::invalid_argument("Invalid file " + filename);
        }

        if (p7_entries.empty() || index >= p7_entries.size()) {
            throw std::logic_error("No proof of space for this challenge");
        }

        // Gets the 64 leaf x values, concatenated together into a k*64 bit string.
        std::vector<Bits> xs = GetInputs(disk_file, p7_entries[index], 6);

        // Sorts them according to proof ordering, where
        // f1(x0) m= f1(x1), f2(x0, x1) m= f2(x2, x3), etc. On disk, they are not stored in
        // proof ordering, they're stored in plot ordering, due to the sorting in the Compress
        // phase.
        std::vector<LargeBits> xs_sorted = ReorderProof(xs);
        for (const auto& x : xs_sorted) {
            full_proof += x;
        }
    }  // Scope for disk_file
    return full_proof;
}

std::pair<std::vector<LargeBits>, std::vector<uint64_t >>
DiskProver::GetQualitiesAndEntriesForChallenge(const uint8_t *challenge) {
    std::vector<LargeBits> qualities;

    std::lock_guard<std::mutex> l(_mtx);
    std::vector<uint64_t> p7_entries;

    {
        std::ifstream disk_file(filename, std::ios::in | std::ios::binary);

        if (!disk_file.is_open()) {
            throw std::invalid_argument("Invalid file " + filename);
        }

        // This tells us how many f7 outputs (and therefore proofs) we have for this
        // challenge. The expected value is one proof.
        p7_entries = GetP7Entries(disk_file, challenge);

        if (p7_entries.empty()) {
            return std::make_pair(std::vector<LargeBits>(), std::vector<uint64_t>());
        }

        // The last 5 bits of the challenge determine which route we take to get to
        // our two x values in the leaves.
        uint8_t last_5_bits = challenge[31] & 0x1f;

        std::vector<std::future<LargeBits>> qualities_futs{};

        for (uint64_t position : p7_entries) {
            auto f = std::async(std::launch::async, [this, &disk_file, position, last_5_bits, challenge]() mutable {
                // This inner loop goes from table 6 to table 1, getting the two backpointers,
                // and following one of them.
                for (uint8_t table_index = 6; table_index > 1; table_index--) {
                    uint128_t line_point = ReadLinePoint(disk_file, table_index, position);

                    auto xy = Encoding::LinePointToSquare(line_point);
                    assert(xy.first >= xy.second);

                    if (((last_5_bits >> (table_index - 2)) & 1) == 0) {
                        position = xy.second;
                    } else {
                        position = xy.first;
                    }
                }
                uint128_t new_line_point = ReadLinePoint(disk_file, 1, position);
                auto x1x2 = Encoding::LinePointToSquare(new_line_point);

                // The final two x values (which are stored in the same location) are hashed
                std::vector<unsigned char> hash_input(32 + Util::ByteAlign(2 * k) / 8, 0);
                memcpy(hash_input.data(), challenge, 32);
                (LargeBits(x1x2.second, k) + LargeBits(x1x2.first, k))
                        .ToBytes(hash_input.data() + 32);
                std::vector<unsigned char> hash(picosha2::k_digest_size);
                picosha2::hash256(hash_input.begin(), hash_input.end(), hash.begin(), hash.end());
                return LargeBits(hash.data(), 32, 256);
//                qualities.emplace_back(hash.data(), 32, 256);
            });
            qualities_futs.emplace_back(std::move(f));
        }

        for (auto &f: qualities_futs) {
            qualities.emplace_back(f.get());
        }
    }  // Scope for disk_file
    return std::make_pair(qualities, p7_entries);
}
