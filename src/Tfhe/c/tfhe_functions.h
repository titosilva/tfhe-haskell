#pragma once

#include <stdint.h>

void generate_key_pair(int ctx);
void create_encrypted_16bit_input_node(int ctx, int input_id, int16_t plaintext);
void compute_16bit_minimum(int ctx, int out_id, int input1, int input2);
int16_t decrypt_16bit_node(int ctx, int node_id);