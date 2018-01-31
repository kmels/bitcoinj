/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;

/**
 * Created by jimmy on 9/29/17.
 */

public class Bip47Address {

    private String address;
    private int index = 0;
    private boolean seen = false;

    public Bip47Address() {}

    public Bip47Address(String address, int index) {
        this.address = address;
        this.index = index;
    }

    public Bip47Address(String address, int index, boolean seen) {
        this(address, index);
        this.seen = seen;
    }

    public String getAddress() {
        return address;
    }

    public int getIndex() {
        return index;
    }

    public boolean isSeen() {
        return seen;
    }

    public void setSeen(boolean seen) {
        this.seen = seen;
    }

    @Override
    public String toString() {
        return address;
    }
}
