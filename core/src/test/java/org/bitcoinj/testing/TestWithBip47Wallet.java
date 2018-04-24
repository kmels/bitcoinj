package org.bitcoinj.testing;

import org.bitcoinj.wallet.bip47.BIP47Wallet;

public class TestWithBip47Wallet extends TestWithWallet {
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    public void setWallet(BIP47Wallet w){
        this.wallet = w.getvWallet();
    }
}
