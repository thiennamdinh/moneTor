 /**
 * This module implements minimal ledger for operating the moneTor payment
 * system. It most closely models the Ethereum ledger paradigm in which accounts
 * are maintained in the form of address->data pairings. This means that the
 * entire state of the system is immediately accessible at any time, which
 * stands in contrast to bitcoin model which keeps a permanent log of historical
 * events. The moneTor ledger currently recognizes two types of addresses:
 *
 *     Standard - Normal address owned by a user which can be used to transfer
 *     funds on the ledger
 *
 *     Channel - Special address that is used by two people to hold
 *     ledger-information about an open micropayment channel between the two
 *     parties. Channels are modeled as a simple state machine (states
 *     enumerated in chn_state) with some external information about balances
 *     and timeouts.
 *
 * The outward-facing interface for the ledger consist of two methods:
 *
 *     post() - Accepts a message to update the ledger state
 *     query() - Accepts a message to retrieve information about the ledger
 *
 * Unless otherwise noted, all functions return 0 for success or -1 for failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_utils.h"
#include "mt_ledger.h"

GTree* mac_accounts;           // mapping from addresses to ledger entries
GTree* chn_accounts;           // mapping from add

byte pp[SIZE_PP];           // public parameters for zkp verification
int fee;                    // nominal fee for publishing to the ledger
double tax;                    // intermediary tax for incentive redistribution
int epoch;                  // discrete monotonic ledger time
int close_window;           // time allotted to refute channel closure (epochs)

byte roger[SIZE_ADDR];     // Tor authority address

byte ledger_pk[SIZE_PK];
byte ledger_sk[SIZE_SK];
byte ledger_addr[SIZE_ADDR];

int addr_compare(gconstpointer a, gconstpointer b){
    return memcmp(a, b, SIZE_ADDR);
}

/**
 * Called at the system setup to create brand new ledger.
 */
int ledger_setup(byte (*p_pp)[SIZE_PP], int p_fee, double p_tax, int p_close_window,
	  byte (*roger_pk)[SIZE_PK]){

    // initialize state
    mac_accounts = g_tree_new((GCompareFunc) addr_compare);
    chn_accounts = g_tree_new((GCompareFunc) addr_compare);

    if(mac_accounts == NULL || chn_accounts == NULL)
	return MT_ERROR;

    // set ledger attributes
    memcpy(pp, p_pp, SIZE_PP);
    fee = p_fee;
    tax = p_tax;
    close_window = p_close_window;
    epoch = 0;

    // add roger's address as the first node in the state
    if(pk_to_addr(roger_pk, &roger) != MT_SUCCESS)
	return MT_ERROR;

    // generate ledger keys/address
    paycrypt_keygen(&pp, &ledger_pk, &ledger_sk);
    if(pk_to_addr(&ledger_pk, &ledger_addr) != MT_SUCCESS)
	return MT_ERROR;

    g_tree_insert(mac_accounts, roger, calloc(1, sizeof(mac_led_data)));
    return MT_SUCCESS;
}

void update_epoch(){
    //TODO: either check clock or receive external output
}

/**
 * Request to publish any type of information at all go to this function. The
 * function is responsible for parsing the message to interpret what should be
 * done with the request.
 */
int post(byte* str) {

    byte pk[SIZE_PK];
    byte addr[SIZE_ADDR];
    int result;

    switch(token_type(str)){
	case NTYPE_MAC_AUT_MINT:;
	    mac_aut_mint mac_aut_mint_tkn;
	    if(unpack_mac_aut_mint(str, &mac_aut_mint_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_mac_aut_mint(mac_aut_mint_tkn, &addr);
	    break;

	case NTYPE_MAC_ANY_TRANS:;
	    mac_any_trans mac_any_trans_tkn;
	    if(unpack_mac_any_trans(str, &mac_any_trans_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_mac_any_trans(mac_any_trans_tkn, &addr);
	    break;

	case NTYPE_CHN_END_ESCROW:;
	    chn_end_escrow chn_end_escrow_tkn;
	    if(unpack_chn_end_escrow(str, &chn_end_escrow_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_chn_end_escrow(chn_end_escrow_tkn, &addr);
	    break;

	case NTYPE_CHN_INT_ESCROW:;
	    chn_int_escrow chn_int_escrow_tkn;
	    if(unpack_chn_int_escrow(str, &chn_int_escrow_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_chn_int_escrow(chn_int_escrow_tkn, &addr);
	    break;

	case NTYPE_CHN_INT_REQCLOSE:;
	    chn_int_reqclose chn_int_reqclose_tkn;
	    if(unpack_chn_int_reqclose(str, &chn_int_reqclose_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_chn_int_reqclose(chn_int_reqclose_tkn, &addr);
	    break;

	case NTYPE_CHN_END_CLOSE:;
	    chn_end_close chn_end_close_tkn;
	    if(unpack_chn_end_close(str, &chn_end_close_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_chn_end_close(chn_end_close_tkn, &addr);
	    break;

	case NTYPE_CHN_INT_CLOSE:;
	    chn_int_close chn_int_close_tkn;
	    if(unpack_chn_int_close(str, &chn_int_close_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_chn_int_close(chn_int_close_tkn, &addr);
	    break;

	case NTYPE_CHN_END_CASHOUT:;
	    chn_end_cashout chn_end_cashout_tkn;
	    if(unpack_chn_end_cashout(str, &chn_end_cashout_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_chn_end_cashout(chn_end_cashout_tkn, &addr);
	    break;

	case NTYPE_CHN_INT_CASHOUT:;
	    chn_int_cashout chn_int_cashout_tkn;
	    if(unpack_chn_int_cashout(str, &chn_int_cashout_tkn, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    pk_to_addr(&pk, &addr);
	    result = handle_chn_int_cashout(chn_int_cashout_tkn, &addr);
	    break;

	default:
	    result = MT_ERROR;
    }
    return result;
}

/**
 * Processes a request to query data at a given address
 */
int query(byte* str, byte** data_out){

    byte pk[SIZE_PK];

    int result = MT_SUCCESS;
    switch(token_type(str)){
	case NTYPE_MAC_LED_QUERY:;
	    mac_led_query mac_query;
	    if(unpack_mac_led_query(str, &mac_query, &pk) != MT_SUCCESS)
		return MT_ERROR;
	    mac_led_data* mac_ptr = g_tree_lookup(mac_accounts, mac_query.addr);

	    // check that address exists
	    if(mac_ptr == NULL)
		return MT_ERROR;

	    if(pack_mac_led_data(*mac_ptr, &ledger_pk, &ledger_sk, data_out) ==  MT_ERROR)
		return MT_ERROR;

	    result = MT_SUCCESS;
	    break;

	case NTYPE_CHN_LED_QUERY:;

	    chn_led_query chn_query;
	    if(unpack_chn_led_query(str, &chn_query, &pk) != MT_SUCCESS)
		return MT_ERROR;

	    chn_led_data* chn_ptr = g_tree_lookup(chn_accounts, chn_query.addr);

	    // check that address exists
	    if(chn_ptr == NULL)
		return MT_ERROR;

	    if(pack_chn_led_data(*chn_ptr, &ledger_pk, &ledger_sk, data_out) == MT_ERROR)
		return MT_ERROR;

	    result = MT_SUCCESS;
	    break;

	default:
	    result = MT_ERROR;
    }
    return result;
}

//---------------------------- Transaction Handler Functions ----------------------------//

/**
 * Mints the specified amount of new funds and adds it to roger's account.
 */
int handle_mac_aut_mint(mac_aut_mint token, byte (*addr)[SIZE_ADDR]){

    // make sure the message is signed by the ledger authority
    if(memcmp(roger, addr, SIZE_ADDR) != 0)
	return MT_ERROR;

    // make sure value isn't negative for some reason
    if(token.value < 0)
	return MT_ERROR;

    // address is guaranteed to exist if module was setup with init()
    mac_led_data* data = g_tree_lookup(mac_accounts, roger);
    data->balance += token.value;
    return MT_SUCCESS;
}

/**
 * Handles a transfer of funds between two standard balances.
 */
int handle_mac_any_trans(mac_any_trans token, byte (*addr)[SIZE_ADDR]){

    // check that the message originates from the payer
    if(memcmp(addr, token.from, SIZE_ADDR) != 0)
	return MT_ERROR;

    mac_led_data* data_from = g_tree_lookup(mac_accounts, token.from);

    // check that the "from" address exists
    if(data_from == NULL)
	return MT_ERROR;

    mac_led_data* data_to = g_tree_lookup(mac_accounts, token.to);
    // if the address doesn't exist then create it

    if(data_to == NULL){
	byte* new_addr = malloc(SIZE_ADDR);
	memcpy(new_addr, token.to, SIZE_ADDR);
	data_to = calloc(1, sizeof(mac_led_data));
	g_tree_insert(mac_accounts, new_addr, data_to);
    }

    int* bal_from = &(data_from->balance);
    int* bal_to = &(data_to->balance);
    transfer(bal_from, bal_to, token.val_from, token.val_to, fee);
    return 0;
}

/**
 * Initializes a new channel address using escrowed funds from a standard
 * address. The initializing user is considered to be the end user in this
 * channel. At this point, the channel is not very useful since the intermediary
 * has not completed the setup, but the funds are still recoverable.
 */
int handle_chn_end_escrow(chn_end_escrow token, byte (*addr)[SIZE_ADDR]){

    // check that the message originates from the payer
    if(memcmp(addr, token.from, SIZE_ADDR) != 0)
	return MT_ERROR;

    mac_led_data* data_from = g_tree_lookup(mac_accounts, token.from);
    chn_led_data* data_chn = g_tree_lookup(chn_accounts, token.chn);

    // check that the from address exists
    if(data_from == NULL)
	return MT_ERROR;

    // if the channel doesn't exist then create one
    if(data_chn == NULL){
	byte* new_addr = malloc(SIZE_ADDR);
	memcpy(new_addr, token.chn, SIZE_ADDR);
	data_chn = calloc(1, sizeof(chn_led_data));
	data_chn->state = CSTATE_EMPTY;
	g_tree_insert(chn_accounts, new_addr, data_chn);
    }

    // check that we have a new and unused channel address
    if(data_chn->state != CSTATE_EMPTY)
	return MT_ERROR;

    int* bal_from = &(data_from->balance);
    int* bal_to = &(data_chn->end_balance);

    // check that the escrow transfer goes through
    if(transfer(bal_from, bal_to, token.val_from, token.val_to, fee) == MT_ERROR){
	return MT_ERROR;
    }

    memcpy(data_chn->end_addr, addr, SIZE_ADDR);
    data_chn->end_chn_token = token.chn_token;
    data_chn->state = CSTATE_INIT;
    return 0;
}

/**
 * Respond to an existing initialized channel to serve as the channel
 * intermediary. Once this operation completes, the channel is considered open
 * for micro/nanopayment processing. Funds will not be recoverable until the
 * channel closure protocol is completed by both parties.
 */
int handle_chn_int_escrow(chn_int_escrow token, byte (*addr)[SIZE_ADDR]){

    // check that the message originates from the payer
    if(memcmp(addr, token.from, SIZE_ADDR) != 0)
	return MT_ERROR;

    mac_led_data* data_from = g_tree_lookup(mac_accounts, token.from);
    chn_led_data* data_chn = g_tree_lookup(chn_accounts, token.chn);

    // check that both channels exist
    if(data_from == NULL || data_chn == NULL)
	return MT_ERROR;

    // check that the channel address is in the right state
    if(data_chn->state != CSTATE_INIT)
	return MT_ERROR;

    int* bal_from = &(data_from->balance);
    int* bal_to = &(data_chn->int_balance);

    // check that the escrow transfer goes through
    if(transfer(bal_from, bal_to, token.val_from, token.val_to, fee) == MT_ERROR)
	return MT_ERROR;

    memcpy(data_chn->int_addr, addr, SIZE_ADDR);
    data_chn->int_chn_token = token.chn_token;
    data_chn->state = CSTATE_OPEN;
    return 0;
}

/**
 * Request by the intermediary to close out a channel. At this point, the
 * intermediary does not know what the final balances should be. As a result,
 * the end user must respond with a closure message within the specified time
 * limit or risk losing the entire balance of her funds.
 */
int handle_chn_int_reqclose(chn_int_reqclose token, byte (*addr)[SIZE_ADDR]){

    chn_led_data* data_chn = g_tree_lookup(chn_accounts, token.chn);

    // check that the channel address exists
    if(data_chn == NULL)
	return MT_ERROR;

    // check that message is coming from the intermediary
    if(memcmp(data_chn->int_addr, addr, SIZE_ADDR) != 0)
	return MT_ERROR;

    // check that the channel is in the right state
    if(!(data_chn->state == CSTATE_OPEN))
	return MT_ERROR;

    data_chn->close_epoch = epoch + close_window;
    data_chn->state = CSTATE_INT_REQCLOSED;
    return 0;
}

/**
 * Request by the end user to close out a channel. The end user posts her view
 * of the current channel balance. The intermediary now has some specified time
 * limit to refute the claim before the channel can be cashed out.
 */
int handle_chn_end_close(chn_end_close token, byte (*addr)[SIZE_ADDR]){

    chn_led_data* data_chn = g_tree_lookup(chn_accounts, token.chn);

    // check that the channel address exists
    if(data_chn == NULL)
	return MT_ERROR;

    // check that message is coming from the end user
    if(memcmp(data_chn->end_addr, addr, SIZE_ADDR) != 0)
	return MT_ERROR;

    // check that the channel is in the right state
    if(!(data_chn->state == CSTATE_OPEN || data_chn->state == CSTATE_INT_REQCLOSED))
	return MT_ERROR;

    data_chn->end_close_token = token;
    data_chn->close_epoch = epoch + close_window;
    data_chn->state = CSTATE_END_CLOSED;
    return 0;
}

/**
 * Operation by the intermediary to either accept the end user's view of the
 * channel balances or refute the claim with another view. The network resolves
 * the dispute and outputs the final channel balances.
 */
int handle_chn_int_close(chn_int_close token, byte (*addr)[SIZE_ADDR]){

    chn_led_data* data_chn = g_tree_lookup(chn_accounts, token.chn);

    // check that the channel address exists and is a channel address
    if(data_chn == NULL)
	return MT_ERROR;

    // check that message is coming from the intermediary
    if(memcmp(data_chn->int_addr, addr, SIZE_ADDR) != 0)
	return MT_ERROR;

    // check that the channel address is in the right state
    if(!(data_chn->state == CSTATE_END_CLOSED))
	return MT_ERROR;

    data_chn->int_close_token = token;
    data_chn->state = CSTATE_INT_CLOSED;
    return 0;
}

/**
 * Operation by the end user to cash out of a payment channel. This can only be
 * done by the end user if the channel has not been initialized by the
 * intermediary or after the channel has/should be closed.
 */
int handle_chn_end_cashout(chn_end_cashout token, byte (*addr)[SIZE_ADDR]){

    chn_led_data* data_chn = g_tree_lookup(chn_accounts, token.chn);

    // check that the channel address exists
    if(data_chn == NULL)
	return MT_ERROR;

    // check that the from address is the channel end user
    if(memcmp(addr, data_chn->end_addr, SIZE_ADDR))
	return MT_ERROR;

    mac_led_data* data_to = g_tree_lookup(mac_accounts, addr);

    // attempt to close the channel if it isn't already
    if(close_channel(data_chn) == MT_ERROR)
	return MT_ERROR;

    int* bal_from = &(data_chn->end_balance);
    int* bal_to = &(data_to->balance);

    // check that the transfer goes through
    return transfer(bal_from, bal_to, token.val_from, token.val_to, fee);
}

/**
 * Operation by the intermediary to cash out of a payment channel. This can only
 * be done after the channel has/should be closed.
 */
int handle_chn_int_cashout(chn_int_cashout token, byte (*addr)[SIZE_ADDR]){

    chn_led_data* data_chn = g_tree_lookup(chn_accounts, token.chn);

    // check that the channel address exists
    if(data_chn == NULL)
	return MT_ERROR;

    // check that the from address is the channel intermediary
    if(memcmp(addr, data_chn->int_addr, SIZE_ADDR))
	return MT_ERROR;

    mac_led_data* data_to = g_tree_lookup(mac_accounts, addr);

    // attempt to close the channel if it isn't already
    if(close_channel(data_chn) == MT_ERROR)
	return MT_ERROR;

    int* bal_from = &(data_chn->int_balance);
    int* bal_to = &(data_to->balance);

    // check that the transfer goes through
    int val_roger = fee + token.val_to * tax;
    return transfer(bal_from, bal_to, token.val_from, token.val_to, val_roger);
}

//------------------------------- Helper Functions --------------------------------------//

/**
 * Transfer the specified amounts from one balance to another (provided in
 * pointers). Ensure that the value difference covers the ledger's specified
 * cost of transaction.
 */
int transfer(int* bal_from, int* bal_to, int val_from, int val_to, int val_roger){
    // check that the payment values make sense
    if(!(val_from > val_to && val_to > 0))
	return MT_ERROR;

    // check that the payer has a sufficient balance
    if(*bal_from < val_from)
	return MT_ERROR;
    // check that the payment different covers the ledger profit
    if(val_from - val_to < val_roger)
	return MT_ERROR;

    *bal_from -= val_from;
    *bal_to += val_to;

    mac_led_data* roger_data = g_tree_lookup(mac_accounts, roger);
    roger_data->balance += (val_from - val_to);
    return 0;
}

/**
 * Process a request to close the given channel. This function considers all
 * possible states of the channel. If channel closure is allowed, then it marks
 * the channel as closed and updates the final balances.
 */
int close_channel(chn_led_data* data){

    // channel is already closed
    if(data->state == CSTATE_RESOLVED)
	return 0;

    // cannot close channel
    if(data->state == CSTATE_EMPTY || data->state == CSTATE_OPEN)
	return MT_ERROR;

    // one part has closed the channel but not enough time has passed
    if((data->state == CSTATE_INT_REQCLOSED || data->state == CSTATE_END_CLOSED) &&
	data->close_epoch + close_window < epoch)
	return MT_ERROR;

    int* end_bal = NULL;
    int* int_bal = NULL;
    resolve(&pp, data->end_chn_token, data->int_chn_token,
	    data->end_close_token, data->int_close_token, end_bal, int_bal);

    if(end_bal != NULL && int_bal != NULL){
	data->end_balance = *end_bal;
	data->int_balance = *int_bal;
    }

    data->state = CSTATE_RESOLVED;
    return 0;
}

//------------------------------- moneTor Algorithms ------------------------------------//

/**
 * Resolve algorithm implemente from the moneTor protocol algorithms. Accepts
 * channel information at closure and makes a determination on the final balances.
 */
void resolve(byte (*pp)[SIZE_PP], chn_end_chntok T_E, chn_int_chntok T_I,
	    chn_end_close rc_E, chn_int_close rc_I, int* end_bal, int* int_bal){}
