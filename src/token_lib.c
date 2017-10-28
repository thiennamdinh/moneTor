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

#include <stdlib.h>
#include <string.h>

#include "token_lib.h"

ttype token_type(byte* str){
    return *((ttype*)str);
}

int pack_chn_end_chantok(chn_end_chantok token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_end_chantok);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_END_CHANTOK;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_end_chantok));
    return size;
}

int pack_chn_int_chantok(chn_int_chantok token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_int_chantok);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_INT_CHANTOK;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_int_chantok));
    return size;
}

int pack_nan_any_chantok(nan_any_chantok token, byte** str_out){
    int size = sizeof(ttype) + sizeof(nan_any_chantok);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_NAN_ANY_CHANTOK;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(nan_any_chantok));
    return size;
}

int pack_chn_end_revoke(chn_end_revoke token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_end_revoke);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_END_REVOKE;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_end_revoke));
    return size;
}

int pack_chn_end_refund(chn_end_refund token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_end_refund);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_END_REFUND;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_end_refund));
    return size;
}

int pack_mac_aut_mint(mac_aut_mint token, byte** str_out){
    int size = sizeof(ttype) + sizeof(mac_aut_mint);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_MAC_AUT_MINT;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(mac_aut_mint));
    return size;
}

int pack_mac_any_trans(mac_any_trans token, byte** str_out){
    int size = sizeof(ttype) + sizeof(mac_any_trans);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_MAC_ANY_TRANS;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(mac_any_trans));
    return size;
}

int pack_chn_end_escrow(chn_end_escrow token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_end_escrow);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_END_ESCROW;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_end_escrow));
    return size;
}

int pack_chn_int_escrow(chn_int_escrow token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_int_escrow);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_INT_ESCROW;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_int_escrow));
    return size;
}

int pack_chn_int_reqclose(chn_int_reqclose token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_int_reqclose);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_INT_REQCLOSE;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_int_reqclose));
    return size;
}

int pack_chn_end_close(chn_end_close token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_end_close);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_END_CLOSE;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_end_close));
    return size;
}

int pack_chn_int_close(chn_int_close token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_int_close);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_INT_CLOSE;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_int_close));
    return size;
}

int pack_chn_end_cashout(chn_end_cashout token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_end_cashout);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_END_CASHOUT;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_end_cashout));
    return size;
}

int pack_chn_int_cashout(chn_int_cashout token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_int_cashout);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_INT_CASHOUT;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_int_cashout));
    return size;
}

int pack_mac_led_data(mac_led_data token, byte** str_out){
    int size = sizeof(ttype) + sizeof(mac_led_data);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_MAC_LED_DATA;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(mac_led_data));
    return size;
}

int pack_chn_led_data(chn_led_data token, byte** str_out){
    int size = sizeof(ttype) + sizeof(chn_led_data);
    *str_out = (byte*)malloc(size);
    **str_out = TTYPE_CHN_LED_DATA;
    memcpy(*str_out + sizeof(ttype), &token, sizeof(chn_led_data));
    return size;
}

chn_end_chantok unpack_chn_end_chantok(byte* str){
    chn_end_chantok token = *(chn_end_chantok*)(str + sizeof(ttype));
    return token;
}

chn_int_chantok unpack_chn_int_chantok(byte* str){
    chn_int_chantok token = *(chn_int_chantok*)(str + sizeof(ttype));
    return token;
}

nan_any_chantok unpack_nan_any_chantok(byte* str){
    nan_any_chantok token = *(nan_any_chantok*)(str + sizeof(ttype));
    return token;
}

chn_end_revoke unpack_chn_end_revoke(byte* str){
    chn_end_revoke token = *(chn_end_revoke*)(str + sizeof(ttype));
    return token;
}

chn_end_refund unpack_chn_end_refund(byte* str){
    chn_end_refund token = *(chn_end_refund*)(str + sizeof(ttype));
    return token;
}

mac_aut_mint unpack_mac_aut_mint(byte* str){
    mac_aut_mint token = *(mac_aut_mint*)(str + sizeof(ttype));
    return token;
}

mac_any_trans unpack_mac_any_trans(byte* str){
    mac_any_trans token = *(mac_any_trans*)(str + sizeof(ttype));
    return token;
}

chn_end_escrow unpack_chn_end_escrow(byte* str){
    chn_end_escrow token = *(chn_end_escrow*)(str + sizeof(ttype));
    return token;
}

chn_int_escrow unpack_chn_int_escrow(byte* str){
    chn_int_escrow token = *(chn_int_escrow*)(str + sizeof(ttype));
    return token;
}

chn_int_reqclose unpack_chn_int_reqclose(byte* str){
    chn_int_reqclose token = *(chn_int_reqclose*)(str + sizeof(ttype));
    return token;
}

chn_end_close unpack_chn_end_close(byte* str){
    chn_end_close token = *(chn_end_close*)(str + sizeof(ttype));
    return token;
}

chn_int_close unpack_chn_int_close(byte* str){
    chn_int_close token = *(chn_int_close*)(str + sizeof(ttype));
    return token;
}

chn_end_cashout unpack_chn_end_cashout(byte* str){
    chn_end_cashout token = *(chn_end_cashout*)(str + sizeof(ttype));
    return token;
}

chn_int_cashout unpack_chn_int_cashout(byte* str){
    chn_int_cashout token = *(chn_int_cashout*)(str + sizeof(ttype));
    return token;
}

mac_led_data unpack_mac_led_data(byte* str){
    mac_led_data token = *(mac_led_data*)(str + sizeof(ttype));
    return token;
}

chn_led_data unpack_chn_led_data(byte* str){
    chn_led_data token = *(chn_led_data*)(str + sizeof(ttype));
    return token;
}

mac_led_query unpack_mac_led_query(byte* str){
    mac_led_query token = *(mac_led_query*)(str + sizeof(ttype));
    return token;
}

chn_led_query unpack_chn_led_query(byte* str){
    chn_led_query token = *(chn_led_query*)(str + sizeof(ttype));
    return token;
}
