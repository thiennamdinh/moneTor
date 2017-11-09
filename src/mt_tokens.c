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

#include "mt_tokens.h"

//---------------------------- General Functions ----------------------------//

/**
 * Extracts the claimed token type of the message
 */
ntype token_type(byte* str){
    return (ntype)*str;
}

int pack_token(ntype type, void* ptr, int size, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    int str_size = sizeof(ntype) + size + SIZE_PK + SIZE_SIG;
    byte* str = malloc(str_size);
    memcpy(str, &type, sizeof(type));
    memcpy(str + sizeof(ntype), ptr, size);
    memcpy(str + sizeof(ntype) + size, *pk, SIZE_PK);

    byte sig[SIZE_SIG];
    if(sig_sign(str, sizeof(ntype) + size, sk, &sig) != MT_SUCCESS)
    	return MT_ERROR;
    memcpy(str + sizeof(ntype) + size + SIZE_PK, sig, SIZE_SIG);

    *str_out = str;
    return str_size;
}

int unpack_token(ntype type, byte* str, int struct_size, void* struct_out, byte(*pk_out)[SIZE_PK]){
    if(token_type(str) != type)
	return MT_ERROR;

    byte pk[SIZE_PK];
    byte sig[SIZE_SIG];
    memcpy(pk, str + sizeof(ntype) + struct_size, SIZE_PK);
    memcpy(sig, str + sizeof(ntype) + struct_size + SIZE_PK, SIZE_SIG);

    if(sig_verify(str, sizeof(ntype) + struct_size, &pk, &sig) != MT_SUCCESS)
	return MT_ERROR;

    memcpy(struct_out, str + sizeof(ntype), struct_size);
    memcpy(*pk_out, pk, SIZE_PK);
    return MT_SUCCESS;
}

//------------------------ Token-specific Functions -------------------------//

int pack_mac_aut_mint(mac_aut_mint token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MAC_AUT_MINT, &token, sizeof(token), pk, sk, str_out);
}

int pack_mac_any_trans(mac_any_trans token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MAC_ANY_TRANS, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_end_escrow(chn_end_escrow token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_END_ESCROW, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_int_escrow(chn_int_escrow token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_INT_ESCROW, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_int_reqclose(chn_int_reqclose token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_INT_REQCLOSE, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_end_close(chn_end_close token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_END_CLOSE, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_int_close(chn_int_close token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_INT_CLOSE, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_end_cashout(chn_end_cashout token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_END_CASHOUT, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_int_cashout(chn_int_cashout token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_INT_CASHOUT, &token, sizeof(token), pk, sk, str_out);
}

int pack_mac_led_data(mac_led_data token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MAC_LED_DATA, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_led_data(chn_led_data token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_LED_DATA, &token, sizeof(token), pk, sk, str_out);
}

int pack_mac_led_query(mac_led_query token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MAC_LED_QUERY, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_led_query(chn_led_query token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_LED_QUERY, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_end_estab1(chn_end_estab1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_END_ESTAB1, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_int_estab2(chn_int_estab2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_INT_ESTAB2, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_end_estab3(chn_end_estab3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_END_ESTAB3, &token, sizeof(token), pk, sk, str_out);
}

int pack_chn_int_estab4(chn_int_estab4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_CHN_INT_ESTAB4, &token, sizeof(token), pk, sk, str_out);
}

int pack_mic_cli_pay1(mic_cli_pay1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MIC_CLI_PAY1, &token, sizeof(token), pk, sk, str_out);
}

int pack_mic_rel_pay2(mic_rel_pay2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MIC_REL_PAY2, &token, sizeof(token), pk, sk, str_out);
}

int pack_mic_cli_pay3(mic_cli_pay3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MIC_CLI_PAY3, &token, sizeof(token), pk, sk, str_out);
}

int pack_mic_int_pay4(mic_int_pay4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MIC_INT_PAY4, &token, sizeof(token), pk, sk, str_out);
}

int pack_mic_cli_pay5(mic_cli_pay5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MIC_CLI_PAY5, &token, sizeof(token), pk, sk, str_out);
}

int pack_mic_rev_pay6(mic_rev_pay6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MIC_REV_PAY6, &token, sizeof(token), pk, sk, str_out);
}

int pack_mic_int_pay7(mic_int_pay7 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MIC_INT_PAY7, &token, sizeof(token), pk, sk, str_out);
}

int pack_mic_int_pay8(mic_int_pay8 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_MIC_INT_PAY8, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_cli_setup1(nan_cli_setup1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_CLI_SETUP1, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_setup2(nan_int_setup2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_SETUP2, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_cli_setup3(nan_cli_setup3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_CLI_SETUP3, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_setup4(nan_int_setup4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_SETUP4, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_cli_setup5(nan_cli_setup5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_CLI_SETUP5, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_setup6(nan_int_setup6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_SETUP6, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_cli_estab1(nan_cli_estab1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_CLI_ESTAB1, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_rel_estab2(nan_rel_estab2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_REL_ESTAB2, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_estab3(nan_int_estab3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_ESTAB3, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_rel_estab4(nan_rel_estab4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_REL_ESTAB4, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_estab5(nan_int_estab5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_ESTAB5, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_end_close1(nan_end_close1 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_END_CLOSE1, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_close2(nan_int_close2 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_CLOSE2, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_end_close3(nan_end_close3 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_END_CLOSE3, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_close4(nan_int_close4 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_CLOSE4, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_end_close5(nan_end_close5 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_END_CLOSE5, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_close6(nan_int_close6 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_CLOSE6, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_end_close7(nan_end_close7 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_END_CLOSE7, &token, sizeof(token), pk, sk, str_out);
}

int pack_nan_int_close8(nan_int_close8 token, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], byte** str_out){
    return pack_token(NTYPE_NAN_INT_CLOSE8, &token, sizeof(token), pk, sk, str_out);
}

//--------------------------------- Unpack --------------------------------//

int unpack_mac_aut_mint(byte* str, mac_aut_mint* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MAC_AUT_MINT, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mac_any_trans(byte* str, mac_any_trans* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MAC_ANY_TRANS, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_end_escrow(byte* str, chn_end_escrow* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_ESCROW, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_int_escrow(byte* str, chn_int_escrow* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_ESCROW, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_int_reqclose(byte* str, chn_int_reqclose* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_REQCLOSE, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_end_close(byte* str, chn_end_close* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_CLOSE, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_int_close(byte* str, chn_int_close* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_CLOSE, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_end_cashout(byte* str, chn_end_cashout* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_CASHOUT, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_int_cashout(byte* str, chn_int_cashout* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_CASHOUT, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mac_led_data(byte* str, mac_led_data* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MAC_LED_DATA, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_led_data(byte* str, chn_led_data* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_LED_DATA, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mac_led_query(byte* str, mac_led_query* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MAC_LED_QUERY, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_led_query(byte* str, chn_led_query* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_LED_QUERY, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_end_estab1(byte* str, chn_end_estab1* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_ESTAB1, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_int_estab2(byte* str, chn_int_estab2* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_ESTAB2, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_end_estab3(byte* str, chn_end_estab3* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_END_ESTAB3, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_chn_int_estab4(byte* str, chn_int_estab4* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_CHN_INT_ESTAB4, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mic_cli_pay1(byte* str, mic_cli_pay1* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_CLI_PAY1, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mic_rel_pay2(byte* str, mic_rel_pay2* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_REL_PAY2, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mic_cli_pay3(byte* str, mic_cli_pay3* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_CLI_PAY3, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mic_int_pay4(byte* str, mic_int_pay4* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_INT_PAY4, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mic_cli_pay5(byte* str, mic_cli_pay5* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_CLI_PAY5, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mic_rev_pay6(byte* str, mic_rev_pay6* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_REV_PAY6, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mic_int_pay7(byte* str, mic_int_pay7* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_INT_PAY7, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_mic_int_pay8(byte* str, mic_int_pay8* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_MIC_INT_PAY8, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_cli_setup1(byte* str, nan_cli_setup1* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_SETUP1, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_int_setup2(byte* str, nan_int_setup2* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_SETUP2, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_cli_setup3(byte* str, nan_cli_setup3* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_SETUP3, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_int_setup4(byte* str, nan_int_setup4* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_SETUP4, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_cli_setup5(byte* str, nan_cli_setup5* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_SETUP5, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_int_setup6(byte* str, nan_int_setup6* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_SETUP6, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_cli_estab1(byte* str, nan_cli_estab1* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_CLI_ESTAB1, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_rel_estab2(byte* str, nan_rel_estab2* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_REL_ESTAB2, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_int_estab3(byte* str, nan_int_estab3* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_ESTAB3, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_rel_estab4(byte* str, nan_rel_estab4* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_REL_ESTAB4, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_int_estab5(byte* str, nan_int_estab5* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_ESTAB5, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_end_close1(byte* str, nan_end_close1* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_END_CLOSE1, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_int_close2(byte* str, nan_int_close2* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_CLOSE2, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_end_close3(byte* str, nan_end_close3* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_END_CLOSE3, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_int_close4(byte* str, nan_int_close4* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_CLOSE4, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_end_close5(byte* str, nan_end_close5* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_END_CLOSE5, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_int_close6(byte* str, nan_int_close6* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_INT_CLOSE6, str, sizeof(*struct_out), struct_out, pk_out);
}

int unpack_nan_end_close7(byte* str, nan_end_close7* struct_out, byte(*pk_out)[SIZE_PK]){
    return unpack_token(NTYPE_NAN_END_CLOSE7, str, sizeof(*struct_out), struct_out, pk_out);
}
