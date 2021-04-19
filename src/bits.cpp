#include "bits.hpp"

template<>
void BitsGeneric<ParkVector>::ToBytes(uint8_t buffer[]) const {
    int i;
    uint8_t tmp[8];

    // Return if nothing to work on
    if (!values_.size())
        return;

    for (i = 0; i < (int) values_.size() - 1; i++) {
        Util::IntToEightBytes(buffer + i * 8, values_[i]);
    }

    Util::IntToEightBytes(tmp, values_[i] << (64 - last_size_));
    memcpy(buffer + i * 8, tmp, cdiv(last_size_, 8));
}


template<>
void BitsGeneric<SmallVector>::ToBytes(uint8_t buffer[]) const {
    int i;
    uint8_t tmp[8];

    // Return if nothing to work on
    if (!values_.size())
        return;

    for (i = 0; i < (int) values_.size() - 1; i++) {
        Util::IntToEightBytes(buffer + i * 8, values_[i]);
    }

    Util::IntToEightBytes(tmp, values_[i] << (64 - last_size_));
    memcpy(buffer + i * 8, tmp, cdiv(last_size_, 8));
}


template<>
void BitsGeneric<LargeVector>::ToBytes(uint8_t buffer[]) const
{
    int i;
    uint8_t tmp[8];

    // Return if nothing to work on
    if (!values_.size())
        return;

    for (i = 0; i < (int)values_.size() - 1; i++) {
        Util::IntToEightBytes(buffer + i * 8, values_[i]);
    }

    Util::IntToEightBytes(tmp, values_[i] << (64 - last_size_));
    memcpy(buffer + i * 8, tmp, cdiv(last_size_, 8));
}