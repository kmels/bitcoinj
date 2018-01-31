/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47.models;

import com.google.common.base.Joiner;

import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.UnreadableWalletException;

import java.security.SecureRandom;

/**
 * Created by jimmy on 9/28/17.
 */

public class StashDeterministicSeed extends DeterministicSeed {
    public StashDeterministicSeed(SecureRandom random, int bits, String passphrase, long creationTimeSeconds) {
        super(random, bits, passphrase, creationTimeSeconds);
    }

    public StashDeterministicSeed(String mnemonicCode, String passphrase, long creationTimeSeconds) throws UnreadableWalletException {
        super(mnemonicCode, null, passphrase, creationTimeSeconds);
    }

    public String getStringMnemonicCode() {
        if (getMnemonicCode() == null) {
            return "";
        }
        return Joiner.on(" ").join(getMnemonicCode());
    }
}
