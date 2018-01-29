package org.bitcoinj.wallet.bip47;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class PaymentCodeTest {

    @Test
    public void testAddressVersion() {
        PaymentCode p = new PaymentCodeBuilder().version(1).build();
        assertEquals('P', p.toBase58().charAt(0));
        assertFalse(p.isValid());
        //assertEquals(0, chain.numKeys());
        //assertFalse(chain.removeKey(key));
    }
}
