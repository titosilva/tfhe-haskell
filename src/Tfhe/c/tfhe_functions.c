#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

// elementary full comparator gate that is used to compare the i-th bit:
//   input: ai and bi the i-th bit of a and b
//          lsb_carry: the result of the comparison on the lowest bits
//   algo: if (a==b) return lsb_carry else return b 
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

// this function compares two multibit words, and puts the max in result
void minimum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    
    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i=0; i<nb_bits; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
    //tmps[0] is the result of the comparaison: 0 if a is larger, 1 if b is larger
    //select the max and copy it to the result
    for (int i=0; i<nb_bits; i++) {
        bootsMUX(&result[i], &tmps[0], &b[i], &a[i], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(2, tmps);    
}

FILE* open_file(int ctx, const char * format, const char * mode) {
    char filename[200];
    sprintf(filename, format, ctx);
    printf("Open %s with mode %s\n", filename, mode);
    FILE* f = fopen(filename, mode);

    if (f == NULL) {
        printf("FAILED!!!\n");
    } else {
        printf("Done\n");
    }

    return f;
}

FILE* open_priv_key_file(int ctx, const char * mode) {
    return open_file(ctx, "/tmp/%d-priv.key", mode);
}

FILE* open_pub_key_file(int ctx, const char * mode) {
    return open_file(ctx, "/tmp/%d-pub.key", mode);
}

FILE* open_params_file(int ctx, const char * mode) {
    return open_file(ctx, "/tmp/%d.params", mode);
}

void write_priv_key_to_file(int ctx, TFheGateBootstrappingSecretKeySet* key) {
    FILE* file = open_priv_key_file(ctx, "wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(file, key);
    fclose(file);
}

void write_pub_key_to_file(int ctx, TFheGateBootstrappingSecretKeySet* key) {
    FILE* file = open_pub_key_file(ctx, "wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(file, &key->cloud);
    fclose(file);
}

void write_params_to_file(int ctx, TFheGateBootstrappingParameterSet* param) {
    FILE* file = open_params_file(ctx, "wb");
    export_tfheGateBootstrappingParameterSet_toFile(file, param);
    fclose(file);
}

void write_cyphertext_array_to_file(int ctx, int node_id, LweSample* ciphertext_array, int array_size, TFheGateBootstrappingParameterSet* params) {
    char filename[200];
    sprintf(filename, "/tmp/%s-node-%d.data", "%d", node_id);

    FILE* data_file = open_file(ctx, filename, "wb");
    for (int i=0; i<array_size; i++) {
        export_gate_bootstrapping_ciphertext_toFile(data_file, &ciphertext_array[i], params);
    }
    fclose(data_file);
}

TFheGateBootstrappingSecretKeySet* read_priv_key_from_file(int ctx) {
    FILE* file = open_priv_key_file(ctx, "rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(file);
    fclose(file);

    return key;
}

TFheGateBootstrappingCloudKeySet* read_pub_key_from_file(int ctx) {
    FILE* file = open_pub_key_file(ctx, "rb");
    TFheGateBootstrappingCloudKeySet* key = new_tfheGateBootstrappingCloudKeySet_fromFile(file);
    fclose(file);

    return key;
}

TFheGateBootstrappingParameterSet* read_params_from_file(int ctx) {
    FILE* file = open_params_file(ctx, "rb");
    TFheGateBootstrappingParameterSet* param = new_tfheGateBootstrappingParameterSet_fromFile(file);
    fclose(file);

    return param;
}

LweSample* read_cyphertext_array_from_file(int ctx, int node_id, int array_size, TFheGateBootstrappingParameterSet* params) {
    LweSample* ciphertext_array = new_gate_bootstrapping_ciphertext_array(16, params);
    char filename[200];
    sprintf(filename, "/tmp/%s-node-%d.data", "%d", node_id);

    FILE* data_file = open_file(ctx, filename, "rb");
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(data_file, &ciphertext_array[i], params);
    fclose(data_file);

    return ciphertext_array;
}

void generate_key_pair(int ctx) {
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    write_params_to_file(ctx, params);
    write_priv_key_to_file(ctx, key);
    write_pub_key_to_file(ctx, key);

    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}

void create_encrypted_16bit_input_node(int ctx, int node_id, int16_t plaintext) {
    TFheGateBootstrappingSecretKeySet* priv_key = read_priv_key_from_file(ctx);
    TFheGateBootstrappingParameterSet* params = read_params_from_file(ctx);

    LweSample* ciphertext_array = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext_array[i], (plaintext>>i)&1, priv_key);
    }

    write_cyphertext_array_to_file(ctx, node_id, ciphertext_array, 16, params);

    delete_gate_bootstrapping_ciphertext_array(16, ciphertext_array);
    delete_gate_bootstrapping_secret_keyset(priv_key);
    delete_gate_bootstrapping_parameters(params);
}

void compute_16bit_minimum(int ctx, int out_node_id, int node1_id, int node2_id) {
    TFheGateBootstrappingCloudKeySet* pub_key = read_pub_key_from_file(ctx);
    TFheGateBootstrappingParameterSet* params = read_params_from_file(ctx);

    LweSample* input1_data = read_cyphertext_array_from_file(ctx, node1_id, 16, params);
    LweSample* input2_data = read_cyphertext_array_from_file(ctx, node2_id, 16, params);

    LweSample* result = new_gate_bootstrapping_ciphertext_array(16, params);
    minimum(result, input1_data, input2_data, 16, pub_key);

    write_cyphertext_array_to_file(ctx, out_node_id, result, 16, params);

    delete_gate_bootstrapping_ciphertext_array(16, input1_data);
    delete_gate_bootstrapping_ciphertext_array(16, input2_data);
    delete_gate_bootstrapping_ciphertext_array(16, result);
    delete_gate_bootstrapping_cloud_keyset(pub_key);
    delete_gate_bootstrapping_parameters(params);
}

int16_t decrypt_16bit_node(int ctx, int node_id) {
    TFheGateBootstrappingSecretKeySet* key = read_priv_key_from_file(ctx);
    TFheGateBootstrappingParameterSet* params = read_params_from_file(ctx);
    LweSample* answer = read_cyphertext_array_from_file(ctx, node_id, 16, params);

    //decrypt and rebuild the 16-bit plaintext answer
    int16_t int_answer = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&answer[i], key);
        int_answer |= (ai<<i);
    }

    delete_gate_bootstrapping_ciphertext_array(16, answer);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return int_answer;
}