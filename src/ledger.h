#ifndef ledger_h
#define ledger_h

void init(byte (*p_pp)[SIZE_PP], int p_fee, int p_tax, int p_close_window,
	  byte (*roger_pk)[SIZE_KEY]);
void update_epoch();

int post(byte* tx_str);
int query(byte* str, byte* data_out);

int execute_mac_aut_mint(byte* msg, byte (*addr)[SIZE_ADDR]);
int execute_mac_any_trans(byte* msg, byte (*addr)[SIZE_ADDR]);
int execute_chn_end_escrow(byte* msg, byte (*addr)[SIZE_ADDR]);
int execute_chn_int_escrow(byte* msg, byte (*addr)[SIZE_ADDR]);
int execute_chn_int_reqclose(byte* msg, byte (*addr)[SIZE_ADDR]);
int execute_chn_end_close(byte* msg, byte (*addr)[SIZE_ADDR]);
int execute_chn_int_close(byte* msg, byte (*addr)[SIZE_ADDR]);
int execute_chn_end_cashout(byte* msg, byte (*addr)[SIZE_ADDR]);
int execute_chn_int_cashout(byte* msg, byte (*addr)[SIZE_ADDR]);

int addr_compare(gconstpointer* a, gconstpointer* b);
int transfer(int* bal_from, int* bal_to, int val_from, int val_to, int val_roger);
int close_channel(chn_led_data* data);

void resolve(byte (*pp)[SIZE_PP], chn_end_chantok T_E, chn_int_chantok T_I,
	     chn_end_close rc_E, chn_int_close rc_I, int* end_bal, int* int_bal);

#endif
