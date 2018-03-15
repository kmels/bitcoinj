/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47.listeners;

import org.bitcoinj.wallet.bip47.Bip47Wallet;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.listeners.TransactionConfidenceEventListener;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;

/**
 * Created by jimmy on 9/29/17.
 */

public abstract class TransactionEventListener implements WalletCoinsReceivedEventListener, TransactionConfidenceEventListener {
    protected Bip47Wallet bip47Wallet;

    public void setBip47Wallet(Bip47Wallet bip47Wallet) {
        this.bip47Wallet = bip47Wallet;
    }

    @Override
    public void onCoinsReceived(org.bitcoinj.wallet.Wallet wallet, Transaction transaction, Coin coin, Coin coin1) {
        onTransactionReceived(this.bip47Wallet, transaction);
    }

    @Override
    public void onTransactionConfidenceChanged(org.bitcoinj.wallet.Wallet wallet, Transaction transaction) {
        onTransactionConfidenceEvent(this.bip47Wallet, transaction);
    }

    public abstract void onTransactionReceived(Bip47Wallet bip47Wallet, Transaction transaction);

    public abstract void onTransactionConfidenceEvent(Bip47Wallet bip47Wallet, Transaction transaction);
}
