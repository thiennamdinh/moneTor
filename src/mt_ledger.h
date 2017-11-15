#ifndef mt_ledger_h
#define mt_ledger_h

#include "mt.h"
#include "mt_tokens.h"

typedef struct {
    mt_send_cb send;

    GTree* mac_accounts;           // mapping from addresses to ledger entries
    GTree* chn_accounts;           // mapping from add

    byte pp[SIZE_PP];           // public parameters for zkp verification
    int fee;                    // nominal fee for publishing to the ledger
    double tax;                    // intermediary tax for incentive redistribution
    int epoch;                  // discrete monotonic ledger time
    int close_window;           // time allotted to refute channel closure (epochs)

    byte roger[SIZE_ADDR];     // Tor authority address

    byte pk[SIZE_PK];
    byte sk[SIZE_SK];
    byte addr[SIZE_ADDR];

} mt_ledger;

// functions necessary to run the ledger
int mt_ledger_init(mt_ledger* ledger, byte (*pp)[SIZE_PP], int fee, double  tax,  int close_window,
		   byte (*roger_pk)[SIZE_PK], mt_send_cb send);

void mt_update_epoch();

// interface for posting/querying ledger data
int mt_ledger_handle(mt_ledger* ledger, cell_t* cell, mt_ctx* ctx);

// transaction logic (delegated by post())
int handle_mac_aut_mint(mt_ledger* ledger, mac_aut_mint* token, byte (*addr)[SIZE_ADDR]);
int handle_mac_any_trans(mt_ledger* ledger, mac_any_trans* token, byte (*addr)[SIZE_ADDR]);
int handle_chn_end_escrow(mt_ledger* ledger, chn_end_escrow* token, byte (*addr)[SIZE_ADDR]);
int handle_chn_int_escrow(mt_ledger* ledger, chn_int_escrow* token, byte (*addr)[SIZE_ADDR]);
int handle_chn_int_reqclose(mt_ledger* ledger, chn_int_reqclose* token, byte (*addr)[SIZE_ADDR]);
int handle_chn_end_close(mt_ledger* ledger, chn_end_close* token, byte (*addr)[SIZE_ADDR]);
int handle_chn_int_close(mt_ledger* ledger, chn_int_close* token, byte (*addr)[SIZE_ADDR]);
int handle_chn_end_cashout(mt_ledger* ledger, chn_end_cashout* token, byte (*addr)[SIZE_ADDR]);
int handle_chn_int_cashout(mt_ledger* ledger, chn_int_cashout* token, byte (*addr)[SIZE_ADDR]);
int handle_mac_led_query(mt_ledger* ledger, mac_led_query* token, mt_ctx* ctx);
int handle_chn_led_query(mt_ledger* ledger, chn_led_query* token, mt_ctx* ctx);

#endif
