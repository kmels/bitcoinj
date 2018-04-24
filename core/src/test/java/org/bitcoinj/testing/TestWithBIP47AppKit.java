package org.bitcoinj.testing;

import org.bitcoinj.wallet.bip47.BIP47AppKit;

public class TestWithBIP47AppKit extends TestWithWallet {
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    public void setWallet(BIP47AppKit w){
        this.wallet = w.getvWallet();
    }
}
