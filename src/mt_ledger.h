#ifndef mt_ledger_h
#define mt_ledger_h

#include "mt_tokens.h"

// functions necessary to run the ledger
int ledger_setup(byte (*p_pp)[SIZE_PP], int p_fee, double p_tax, int p_close_window,
	  byte (*roger_pk)[SIZE_PK]);
void update_epoch();

// interface for posting/querying ledger data
int post(byte* tx_str);
int query(byte* str, byte** data_out);

// transaction logic (delegated by post())
int handle_mac_aut_mint(mac_aut_mint token, byte (*addr)[SIZE_ADDR]);
int handle_mac_any_trans(mac_any_trans token, byte (*addr)[SIZE_ADDR]);
int handle_chn_end_escrow(chn_end_escrow token, byte (*addr)[SIZE_ADDR]);
int handle_chn_int_escrow(chn_int_escrow token, byte (*addr)[SIZE_ADDR]);
int handle_chn_int_reqclose(chn_int_reqclose token, byte (*addr)[SIZE_ADDR]);
int handle_chn_end_close(chn_end_close token, byte (*addr)[SIZE_ADDR]);
int handle_chn_int_close(chn_int_close token, byte (*addr)[SIZE_ADDR]);
int handle_chn_end_cashout(chn_end_cashout token, byte (*addr)[SIZE_ADDR]);
int handle_chn_int_cashout(chn_int_cashout token, byte (*addr)[SIZE_ADDR]);

// helper functions
int addr_compare(gconstpointer a, gconstpointer b);
int transfer(int* bal_from, int* bal_to, int val_from, int val_to, int val_roger);
int close_channel(chn_led_data* data);

// formal protocol algorithm to resolve disputes
void resolve(byte (*pp)[SIZE_PP], chn_end_chntok T_E, chn_int_chntok T_I,
	     chn_end_close rc_E, chn_int_close rc_I, int* end_bal, int* int_bal);

#endif
