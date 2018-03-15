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

/**
 * p>A {@link Bip47Account} is necessary to maintain BIP47 payment channels. It holds the notification key used to derive the
 * notification address and the deterministic key to derive payment addresses in a channel.</p>
 *
 * <p>The BIP47 account is at the derivation path <pre>m / 47' / coin_type' / account_id'.</pre>. </p>
 *
 * <p>Properties:</p>
 * <ul>
 * <li>The coin_type' should be chosen as in BIP43. </li>
 * <li>The account_id is any integer (from 0 to 2147483647)</li>
 * <li>The notification key is derived at: <pre>m / 47' / coin_type' / account_id' / 0 </pre> (non hardened)</li>
 * <li>The payment keys are derived at: <pre>m / 47' / coin_type' / account_id' / idx' </pre> (hardened). </li>
 * </ul>
 */
public class Bip47Account {
    private NetworkParameters params;
    private DeterministicKey key;
    private int accountId;
    private PaymentCode paymentCode;

    /**
     *
     * @param coinType
     * @param identity
     */
    public Bip47Account(NetworkParameters parameters, DeterministicKey coinType, int identity) {
        params = parameters;
        accountId = identity;
        key = HDKeyDerivation.deriveChildKey(coinType, accountId | ChildNumber.HARDENED_BIT);
        paymentCode = new PaymentCode(key.getPubKey(), key.getChainCode());
    }

    public Bip47Account(NetworkParameters parameters, String strPaymentCode) {
        params = parameters;
        accountId = 0;
        key = createMasterPubKeyFromPaymentCode(strPaymentCode);
        paymentCode = new PaymentCode(strPaymentCode);
    }

    public String getStringPaymentCode() {
        return paymentCode.toString();
    }

    public Address getNotificationAddress() {
        return HDKeyDerivation.deriveChildKey(key, ChildNumber.ZERO).toAddress(params);
    }

    public ECKey getNotificationKey() {
        return HDKeyDerivation.deriveChildKey(key, ChildNumber.ZERO);
    }

    public PaymentCode getPaymentCode() {
        return paymentCode;
    }

    public Bip47ChannelAddress addressAt(int idx) {
        return new Bip47ChannelAddress(params, key, idx);
    }

    public ECKey keyAt(int idx) {
        return HDKeyDerivation.deriveChildKey(key, new ChildNumber(idx, false));
    }

    public byte[] getPrivKey(int index) {
        return HDKeyDerivation.deriveChildKey(key, index).getPrivKeyBytes();
    }
}
