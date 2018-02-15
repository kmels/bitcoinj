/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47.listeners;

import org.bitcoinj.core.listeners.OnTransactionBroadcastListener;
import org.bitcoinj.wallet.bip47.Wallet;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.listeners.TransactionConfidenceEventListener;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;

/**
 * Created by jimmy on 9/29/17.
 */

public abstract class TransactionEventListener implements OnTransactionBroadcastListener, WalletCoinsReceivedEventListener, TransactionConfidenceEventListener {
    protected Wallet wallet;

    public void setWallet(Wallet wallet) {
        this.wallet = wallet;
    }

    @Override
    public void onCoinsReceived(org.bitcoinj.wallet.Wallet wallet, Transaction transaction, Coin coin, Coin coin1) {
        onTransactionReceived(this.wallet, transaction);
    }

    @Override
    public void onTransactionConfidenceChanged(org.bitcoinj.wallet.Wallet wallet, Transaction transaction) {
        onTransactionConfidenceEvent(this.wallet, transaction);
    }

    public abstract void onTransactionReceived(Wallet wallet, Transaction transaction);

    public abstract void onTransactionConfidenceEvent(Wallet wallet, Transaction transaction);
}
