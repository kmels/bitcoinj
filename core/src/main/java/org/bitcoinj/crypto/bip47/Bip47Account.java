/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.crypto.bip47;

import org.bitcoinj.wallet.bip47.PaymentCode;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;

import static org.bitcoinj.wallet.bip47.PaymentCode.createMasterPubKeyFromPaymentCode;

/**
 * Created by jimmy on 8/4/17.
 */

public class Bip47Account {
    private NetworkParameters mNetworkParameters;
    private DeterministicKey mKey;
    private int mIndex;
    private PaymentCode mPaymentCode;
    private String mXPub;

    public Bip47Account(NetworkParameters parameters, DeterministicKey deterministicKey, int index) {
        mNetworkParameters = parameters;
        mIndex = index;
        mKey = HDKeyDerivation.deriveChildKey(deterministicKey, mIndex | ChildNumber.HARDENED_BIT);
        mPaymentCode = new PaymentCode(mKey.getPubKey(), mKey.getChainCode());
        mXPub = mKey.serializePubB58(parameters);
    }

    public Bip47Account(NetworkParameters parameters, String strPaymentCode) {
        mNetworkParameters = parameters;
        mIndex = 0;
        mKey = createMasterPubKeyFromPaymentCode(strPaymentCode);
        mPaymentCode = new PaymentCode(strPaymentCode);
        mXPub = mKey.serializePubB58(parameters);
    }

    public String getStringPaymentCode() {
        return mPaymentCode.toString();
    }

    public String getXPub() {
        return mXPub;
    }

    public Address getNotificationAddress() {
        return HDKeyDerivation.deriveChildKey(mKey, ChildNumber.ZERO).toAddress(mNetworkParameters);
    }

    public ECKey getNotificationKey() {
        return HDKeyDerivation.deriveChildKey(mKey, ChildNumber.ZERO);
    }

    public PaymentCode getPaymentCode() {
        return mPaymentCode;
    }

    public org.bitcoinj.crypto.bip47.Address addressAt(int idx) {
        return new org.bitcoinj.crypto.bip47.Address(mNetworkParameters, mKey, idx);
    }

    public ECKey keyAt(int idx) {
        return HDKeyDerivation.deriveChildKey(mKey, new ChildNumber(idx, false));
    }

    public byte[] getPrivKey(int index) {
        return HDKeyDerivation.deriveChildKey(mKey, index).getPrivKeyBytes();
    }
}
