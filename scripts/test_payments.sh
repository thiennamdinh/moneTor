#!/bin/bash

cd ../src

gcc test/test_mt_main.c test/test_mt_crypto.c test/test_mt_tokens.c test/test_mt_common.c test/test_mt_ledger.c mt_tokens.c mt_common.c mt_crypto.c mt_ledger.c -o test/test_mt_main `pkg-config --cflags --libs glib-2.0` -lssl -lcrypto -Wall && test/test_mt_main
