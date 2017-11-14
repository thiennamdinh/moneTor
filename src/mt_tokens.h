#ifndef mt_tokens_h
#define mt_tokens_h

#include <glib.h>

#include "mt.h"
#include "mt_crypto.h" // only needed for the defined byte array sizes

//TODO should probably put these in terms of Tor variables somewhere
#define CELL_SIZE 512


//-------------------------- Pack/Unpack Functions --------------------------//

// extract the token type from the packed message
ntype token_type(cell_t* cell);
int pack_token(ntype type, void* ptr, int size, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int unpack_token(ntype type, cell_t* cell, int struct_size, void* tkn_out, byte(*pk_out)[SIZE_PK]);

// convert semantically meaningful structs to sendable byte strings & sizes

int pack_mac_aut_mint(mac_aut_mint tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mac_any_trans(mac_any_trans tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_end_escrow(chn_end_escrow tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_int_escrow(chn_int_escrow tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_int_reqclose(chn_int_reqclose tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_end_close(chn_end_close tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_int_close(chn_int_close tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_end_cashout(chn_end_cashout tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_int_cashout(chn_int_cashout tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);

int pack_mac_led_data(mac_led_data tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_led_data(chn_led_data tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mac_led_query(mac_led_query tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_led_query(chn_led_query tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);

int pack_chn_end_estab1(chn_end_estab1 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_int_estab2(chn_int_estab2 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_end_estab3(chn_end_estab3 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_chn_int_estab4(chn_int_estab4 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);

int pack_mic_cli_pay1(mic_cli_pay1 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mic_rel_pay2(mic_rel_pay2 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mic_cli_pay3(mic_cli_pay3 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mic_int_pay4(mic_int_pay4 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mic_cli_pay5(mic_cli_pay5 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mic_rev_pay6(mic_rev_pay6 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mic_int_pay7(mic_int_pay7 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_mic_int_pay8(mic_int_pay8 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);

int pack_nan_cli_setup1(nan_cli_setup1 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_setup2(nan_int_setup2 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_cli_setup3(nan_cli_setup3 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_setup4(nan_int_setup4 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_cli_setup5(nan_cli_setup5 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_setup6(nan_int_setup6 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);

int pack_nan_cli_estab1(nan_cli_estab1 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_rel_estab2(nan_rel_estab2 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_estab3(nan_int_estab3 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_rel_estab4(nan_rel_estab4 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_estab5(nan_int_estab5 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);

int pack_nan_cli_pay1(nan_cli_pay1 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);

int pack_nan_end_close1(nan_end_close1 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_close2(nan_int_close2 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_end_close3(nan_end_close3 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_close4(nan_int_close4 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_end_close5(nan_end_close5 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_close6(nan_int_close6 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_end_close7(nan_end_close7 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);
int pack_nan_int_close8(nan_int_close8 tkn, byte(*pk)[SIZE_PK], byte(*sk)[SIZE_SK], cell_t** c_out);

// convert sendable byte strings to semantically meaningful structs

int unpack_mac_aut_mint(cell_t* cell, mac_aut_mint* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mac_any_trans(cell_t* cell, mac_any_trans* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_end_escrow(cell_t* cell, chn_end_escrow* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_escrow(cell_t* cell, chn_int_escrow* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_reqclose(cell_t* cell, chn_int_reqclose* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_end_close(cell_t* cell, chn_end_close* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_close(cell_t* cell, chn_int_close* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_end_cashout(cell_t* cell, chn_end_cashout* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_cashout(cell_t* cell, chn_int_cashout* tkn_out, byte(*pk_out)[SIZE_PK]);

int unpack_mac_led_data(cell_t* cell, mac_led_data* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_led_data(cell_t* cell, chn_led_data* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mac_led_query(cell_t* cell, mac_led_query* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_led_query(cell_t* cell, chn_led_query* tkn_out, byte(*pk_out)[SIZE_PK]);

int unpack_chn_end_estab1(cell_t* cell, chn_end_estab1* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_estab2(cell_t* cell, chn_int_estab2* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_end_estab3(cell_t* cell, chn_end_estab3* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_chn_int_estab4(cell_t* cell, chn_int_estab4* tkn_out, byte(*pk_out)[SIZE_PK]);

int unpack_mic_cli_pay1(cell_t* cell, mic_cli_pay1* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_rel_pay2(cell_t* cell, mic_rel_pay2* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_cli_pay3(cell_t* cell, mic_cli_pay3* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_int_pay4(cell_t* cell, mic_int_pay4* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_cli_pay5(cell_t* cell, mic_cli_pay5* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_rev_pay6(cell_t* cell, mic_rev_pay6* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_int_pay7(cell_t* cell, mic_int_pay7* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_mic_int_pay8(cell_t* cell, mic_int_pay8* tkn_out, byte(*pk_out)[SIZE_PK]);

int unpack_nan_cli_setup1(cell_t* cell, nan_cli_setup1* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_setup2(cell_t* cell, nan_int_setup2* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_cli_setup3(cell_t* cell, nan_cli_setup3* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_setup4(cell_t* cell, nan_int_setup4* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_cli_setup5(cell_t* cell, nan_cli_setup5* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_setup6(cell_t* cell, nan_int_setup6* tkn_out, byte(*pk_out)[SIZE_PK]);

int unpack_nan_cli_estab1(cell_t* cell, nan_cli_estab1* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_rel_estab2(cell_t* cell, nan_rel_estab2* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_estab3(cell_t* cell, nan_int_estab3* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_rel_estab4(cell_t* cell, nan_rel_estab4* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_estab5(cell_t* cell, nan_int_estab5* tkn_out, byte(*pk_out)[SIZE_PK]);

int unpack_nan_cli_pay1(cell_t* cell, nan_cli_pay1* tkn_out, byte(*pk_out)[SIZE_PK]);

int unpack_nan_end_close1(cell_t* cell, nan_end_close1* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_close2(cell_t* cell, nan_int_close2* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_end_close3(cell_t* cell, nan_end_close3* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_close4(cell_t* cell, nan_int_close4* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_end_close5(cell_t* cell, nan_end_close5* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_close6(cell_t* cell, nan_int_close6* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_end_close7(cell_t* cell, nan_end_close7* tkn_out, byte(*pk_out)[SIZE_PK]);
int unpack_nan_int_close8(cell_t* cell, nan_int_close8* tkn_out, byte(*pk_out)[SIZE_PK]);

#endif
