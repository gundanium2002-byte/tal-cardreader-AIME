#pragma once

#include <stdbool.h>
#include <stdint.h>

// Decrypt a raw 16-byte SPAD0 block (Amusement IC user block 0x00).
void spad0_decrypt(const uint8_t in[16], uint8_t out[16]);

// Decrypt SPAD0 and extract the 20-digit access code into `out` (21 bytes incl. NUL).
// Returns false if the block does not contain a valid BCD access code.
bool spad0_access_code(const uint8_t encrypted[16], char out[21]);
