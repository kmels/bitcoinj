/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;

import org.bitcoinj.wallet.bip47.Wallet;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class Bip47Meta {
    private static final String TAG = "Bip47Meta";

    private static final int STATUS_NOT_SENT = -1;
    private static final int STATUS_SENT_CFM = 1;

    private static final int LOOKAHEAD = 10;

    private String paymentCode;
    private String label = "";
    private List<Bip47Address> incomingAddresses = new ArrayList<>();
    private List<String> outgoingAddresses = new ArrayList<>();
    private int status = STATUS_NOT_SENT;
    private int currentOutgoingIndex = 0;
    private int currentIncomingIndex = -1;

    private static final Logger log = LoggerFactory.getLogger(Bip47Meta.class);
    public Bip47Meta() {}

    public Bip47Meta(String paymentCode) {
        this.paymentCode = paymentCode;
    }

    public Bip47Meta(String paymentCode, String label) {
        this(paymentCode);
        this.label = label;
    }

    public String getPaymentCode() {
        return paymentCode;
    }

    public void setPaymentCode(String pc) {
        paymentCode = pc;
    }

    public List<Bip47Address> getIncomingAddresses() {
        return incomingAddresses;
    }

    public int getCurrentIncomingIndex() {
        return currentIncomingIndex;
    }

    public void generateKeys(Wallet wallet) throws NotSecp256k1Exception, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        System.out.println("GENERATING KEYS ...");
        for (int i = 0; i < LOOKAHEAD; i++) {
            ECKey key = BIP47Util.getReceiveAddress(wallet, paymentCode, i).getReceiveECKey();
            Address address = wallet.getAddressOfKey(key);

            log.debug("New address generated");
            System.out.println("New address generated ...");
            log.debug(address.toString());
            System.out.println(address.toString()+" ...");
            wallet.importKey(key);
            incomingAddresses.add(i, new Bip47Address(address.toString(), i));
        }

        currentIncomingIndex = LOOKAHEAD - 1;
    }

    public Bip47Address getIncomingAddress(String address) {
        for (Bip47Address bip47Address: incomingAddresses) {
            if (bip47Address.getAddress().equals(address)) {
                return bip47Address;
            }
        }
        return null;
    }

    public void addNewIncomingAddress(String newAddress, int nextIndex) {
        incomingAddresses.add(nextIndex, new Bip47Address(newAddress, nextIndex));
        currentIncomingIndex = nextIndex;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String l) {
        label = l;
    }

    public List<String> getOutgoingAddresses() {
        return outgoingAddresses;
    }

    public boolean isNotificationTransactionSent() {
        return status == STATUS_SENT_CFM;
    }

    public void setStatusSent() {
        status = STATUS_SENT_CFM;
    }

    public int getCurrentOutgoingIndex() {
        return currentOutgoingIndex;
    }

    public void incrementOutgoingIndex() {
        currentOutgoingIndex++;
    }

    public void addAddressToOutgoingAddresses(String address) {
        outgoingAddresses.add(address);
    }

    public void setStatusNotSent() {
        status = STATUS_NOT_SENT;
    }
}
