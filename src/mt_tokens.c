/**
 * \file token_lib.c
 *
 * Implementation of pack()/unpack() functionality for each multi-party token
 * that enable conversion between semantically meaningful c structs and network
 * sendable byte strings.
 *
 * The current definitions do straightforward casting between structs and byte
 * strings. It may be necessary in more mature versions to explictly define byte
 * allocation in the messages for portability and to add additional meta
 * information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mt_tokens.h"

//---------------------------- General Functions ----------------------------//

/**
 * Extracts the claimed token type of the message
 */
ntype token_type(cell_t* cell){
    return (ntype)(cell->payload[11]);
}

int pack_token(ntype type, void* ptr, int tkn_size, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){

    // copy token information into a temporary message byte string
    int buf_size = tkn_size + SIZE_PK + SIZE_SIG;
    byte buf[buf_size];
    memcpy(buf, ptr, tkn_size);
    memcpy(buf + tkn_size, *pk, SIZE_PK);

    // sign the byte string
    byte sig[SIZE_SIG];
    if(sig_sign(buf, tkn_size, sk, &sig) != MT_SUCCESS)
    	return MT_ERROR;
    memcpy(buf + tkn_size + SIZE_PK, sig, SIZE_SIG);

    // load string into dynamically allocated array of cells
    int num_cells =  (buf_size + MT_PAYLOAD_SIZE -1) / MT_PAYLOAD_SIZE;
    *c_out = malloc(CELL_SIZE * num_cells);

    for(int i = 0; i < num_cells; i++){

	uint16_t cell_length = MT_PAYLOAD_SIZE;
	if(i + 1 == num_cells)
	    cell_length = buf_size % MT_PAYLOAD_SIZE;

	//set relay command
	memcpy((*c_out)[i].payload + 9, &cell_length, sizeof(uint16_t));
        memcpy((*c_out)[i].payload + 11, (uint8_t*)&type, sizeof(uint8_t));
	memcpy((*c_out)[i].payload + 12, buf + (MT_PAYLOAD_SIZE * i), cell_length);
    }

    return num_cells;
}

int unpack_token(ntype type, cell_t* cells, int tkn_size, void* tkn_out, byte(*pk_out)[SIZE_PK]){

    // copy cell contents into a temporary buffer
    int buf_size = tkn_size + SIZE_PK + SIZE_SIG;
    byte buf[buf_size];
    int num_cells =  (buf_size + MT_PAYLOAD_SIZE - 1) / MT_PAYLOAD_SIZE;

    for(int i = 0; i < num_cells; i++){
	if(token_type(&cells[i]) != type)
	    return MT_ERROR;

	uint16_t cell_length;
	memcpy(&cell_length, cells[i].payload + 9, sizeof(uint16_t));
	memcpy(buf + (MT_PAYLOAD_SIZE * i), cells[i].payload + 12, cell_length);
    }

    byte pk[SIZE_PK];
    byte sig[SIZE_SIG];
    memcpy(pk, buf + tkn_size, SIZE_PK);
    memcpy(sig, buf + tkn_size + SIZE_PK, SIZE_SIG);

    if(sig_verify(buf, tkn_size, &pk, &sig) != MT_SUCCESS)
	return MT_ERROR;

    memcpy(tkn_out, buf, tkn_size);
    memcpy(*pk_out, pk, SIZE_PK);
    return MT_SUCCESS;
}

//------------------------ Token-specific Functions -------------------------//

int pack_mac_aut_mint(mac_aut_mint token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MAC_AUT_MINT, &token, sizeof(token), pk, sk, c_out);
}

int pack_mac_any_trans(mac_any_trans token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MAC_ANY_TRANS, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_end_escrow(chn_end_escrow token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_END_ESCROW, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_int_escrow(chn_int_escrow token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_INT_ESCROW, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_int_reqclose(chn_int_reqclose token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_INT_REQCLOSE, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_end_close(chn_end_close token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_END_CLOSE, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_int_close(chn_int_close token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_INT_CLOSE, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_end_cashout(chn_end_cashout token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_END_CASHOUT, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_int_cashout(chn_int_cashout token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_INT_CASHOUT, &token, sizeof(token), pk, sk, c_out);
}

int pack_mac_led_data(mac_led_data token, byte(*pk)[SIZE_PK],   byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MAC_LED_DATA, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_led_data(chn_led_data token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_LED_DATA, &token, sizeof(token), pk, sk, c_out);
}

int pack_mac_led_query(mac_led_query token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MAC_LED_QUERY, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_led_query(chn_led_query token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_LED_QUERY, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_end_estab1(chn_end_estab1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_END_ESTAB1, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_int_estab2(chn_int_estab2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_INT_ESTAB2, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_end_estab3(chn_end_estab3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_END_ESTAB3, &token, sizeof(token), pk, sk, c_out);
}

int pack_chn_int_estab4(chn_int_estab4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_CHN_INT_ESTAB4, &token, sizeof(token), pk, sk, c_out);
}

int pack_mic_cli_pay1(mic_cli_pay1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MIC_CLI_PAY1, &token, sizeof(token), pk, sk, c_out);
}

int pack_mic_rel_pay2(mic_rel_pay2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MIC_REL_PAY2, &token, sizeof(token), pk, sk, c_out);
}

int pack_mic_cli_pay3(mic_cli_pay3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MIC_CLI_PAY3, &token, sizeof(token), pk, sk, c_out);
}

int pack_mic_int_pay4(mic_int_pay4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MIC_INT_PAY4, &token, sizeof(token), pk, sk, c_out);
}

int pack_mic_cli_pay5(mic_cli_pay5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MIC_CLI_PAY5, &token, sizeof(token), pk, sk, c_out);
}

int pack_mic_rev_pay6(mic_rev_pay6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MIC_REV_PAY6, &token, sizeof(token), pk, sk, c_out);
}

int pack_mic_int_pay7(mic_int_pay7 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MIC_INT_PAY7, &token, sizeof(token), pk, sk, c_out);
}

int pack_mic_int_pay8(mic_int_pay8 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_MIC_INT_PAY8, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_cli_setup1(nan_cli_setup1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_CLI_SETUP1, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_setup2(nan_int_setup2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_SETUP2, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_cli_setup3(nan_cli_setup3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_CLI_SETUP3, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_setup4(nan_int_setup4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_SETUP4, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_cli_setup5(nan_cli_setup5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_CLI_SETUP5, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_setup6(nan_int_setup6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_SETUP6, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_cli_estab1(nan_cli_estab1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_CLI_ESTAB1, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_rel_estab2(nan_rel_estab2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_REL_ESTAB2, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_estab3(nan_int_estab3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_ESTAB3, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_rel_estab4(nan_rel_estab4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_REL_ESTAB4, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_estab5(nan_int_estab5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_ESTAB5, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_cli_pay1(nan_cli_pay1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_CLI_PAY1, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_end_close1(nan_end_close1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_END_CLOSE1, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_close2(nan_int_close2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_CLOSE2, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_end_close3(nan_end_close3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_END_CLOSE3, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_close4(nan_int_close4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_CLOSE4, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_end_close5(nan_end_close5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_END_CLOSE5, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_close6(nan_int_close6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_CLOSE6, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_end_close7(nan_end_close7 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_END_CLOSE7, &token, sizeof(token), pk, sk, c_out);
}

int pack_nan_int_close8(nan_int_close8 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out){
    return pack_token(NTYPE_NAN_INT_CLOSE8, &token, sizeof(token), pk, sk, c_out);
}

//--------------------------------- Unpack --------------------------------//

int unpack_mac_aut_mint(cell_t* cells, mac_aut_mint* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MAC_AUT_MINT, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mac_any_trans(cell_t* cells, mac_any_trans* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MAC_ANY_TRANS, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_end_escrow(cell_t* cells, chn_end_escrow* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_ESCROW, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_int_escrow(cell_t* cells, chn_int_escrow* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_ESCROW, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_int_reqclose(cell_t* cells, chn_int_reqclose* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_REQCLOSE, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_end_close(cell_t* cells, chn_end_close* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_CLOSE, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_int_close(cell_t* cells, chn_int_close* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_CLOSE, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_end_cashout(cell_t* cells, chn_end_cashout* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_CASHOUT, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_int_cashout(cell_t* cells, chn_int_cashout* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_CASHOUT, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mac_led_data(cell_t* cells, mac_led_data* tkn_out,  byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MAC_LED_DATA, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_led_data(cell_t* cells, chn_led_data* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_LED_DATA, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mac_led_query(cell_t* cells, mac_led_query* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MAC_LED_QUERY, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_led_query(cell_t* cells, chn_led_query* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_LED_QUERY, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_end_estab1(cell_t* cells, chn_end_estab1* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_ESTAB1, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_int_estab2(cell_t* cells, chn_int_estab2* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_ESTAB2, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_end_estab3(cell_t* cells, chn_end_estab3* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_ESTAB3, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_chn_int_estab4(cell_t* cells, chn_int_estab4* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_ESTAB4, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mic_cli_pay1(cell_t* cells, mic_cli_pay1* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_CLI_PAY1, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mic_rel_pay2(cell_t* cells, mic_rel_pay2* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_REL_PAY2, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mic_cli_pay3(cell_t* cells, mic_cli_pay3* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_CLI_PAY3, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mic_int_pay4(cell_t* cells, mic_int_pay4* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_INT_PAY4, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mic_cli_pay5(cell_t* cells, mic_cli_pay5* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_CLI_PAY5, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mic_rev_pay6(cell_t* cells, mic_rev_pay6* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_REV_PAY6, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mic_int_pay7(cell_t* cells, mic_int_pay7* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_INT_PAY7, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_mic_int_pay8(cell_t* cells, mic_int_pay8* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_INT_PAY8, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_cli_setup1(cell_t* cells, nan_cli_setup1* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_SETUP1, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_int_setup2(cell_t* cells, nan_int_setup2* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_SETUP2, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_cli_setup3(cell_t* cells, nan_cli_setup3* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_SETUP3, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_int_setup4(cell_t* cells, nan_int_setup4* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_SETUP4, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_cli_setup5(cell_t* cells, nan_cli_setup5* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_SETUP5, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_int_setup6(cell_t* cells, nan_int_setup6* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_SETUP6, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_cli_estab1(cell_t* cells, nan_cli_estab1* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_ESTAB1, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_rel_estab2(cell_t* cells, nan_rel_estab2* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_REL_ESTAB2, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_int_estab3(cell_t* cells, nan_int_estab3* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_ESTAB3, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_rel_estab4(cell_t* cells, nan_rel_estab4* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_REL_ESTAB4, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_int_estab5(cell_t* cells, nan_int_estab5* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_ESTAB5, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_cli_pay1(cell_t* cells, nan_cli_pay1* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_PAY1, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_end_close1(cell_t* cells, nan_end_close1* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_END_CLOSE1, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_int_close2(cell_t* cells, nan_int_close2* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_CLOSE2, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_end_close3(cell_t* cells, nan_end_close3* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_END_CLOSE3, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_int_close4(cell_t* cells, nan_int_close4* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_CLOSE4, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_end_close5(cell_t* cells, nan_end_close5* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_END_CLOSE5, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_int_close6(cell_t* cells, nan_int_close6* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_CLOSE6, cells, sizeof(*tkn_out), tkn_out, pk_out);
}

int unpack_nan_end_close7(cell_t* cells, nan_end_close7* tkn_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_END_CLOSE7, cells, sizeof(*tkn_out), tkn_out, pk_out);
}
