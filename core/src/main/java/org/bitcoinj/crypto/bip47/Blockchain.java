/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.crypto.bip47;

import org.bitcoinj.core.NetworkParameters;

public class Blockchain {
    private int mId;
    private NetworkParameters mNetworkParameters;
    private final String mCoin;
    private final String mLabel;


    public Blockchain(int id, NetworkParameters networkParameters, String coin, String label) {
        mId = id;
        mNetworkParameters = networkParameters;
        mCoin = coin;
        mLabel = label;
    }

    public int getId() {
        return mId;
    }

    public void setId(int mId) {
        this.mId = mId;
    }

    public NetworkParameters getNetworkParameters() {
        return mNetworkParameters;
    }

    public void setNetworkParameters(NetworkParameters mNetworkParameters) {
        this.mNetworkParameters = mNetworkParameters;
    }

    public String getCoin() {
        return mCoin;
    }

    public String getLabel() {
        return mLabel;
    }

    @Override
    public String toString() {
        return mLabel;
    }
}