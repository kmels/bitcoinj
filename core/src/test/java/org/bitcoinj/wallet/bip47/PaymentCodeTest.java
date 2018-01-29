package org.bitcoinj.wallet.bip47;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.crypto.*;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class PaymentCodeTest {

    @Test
    public void emptyPubkeyIsInvalid() {
        PaymentCode p = new PaymentCodeBuilder().version(1).build();
        assertEquals('P', p.toBase58().charAt(0));
        assertFalse(p.isValid());
        assertTrue(p.payload.length==80);
    }

    @Test
    public void pubKeyValidates(){
        final ECKey key1 = new ECKey();
        PaymentCode p2 = new PaymentCodeBuilder().version(1).pubKey(key1.getPubKey()).build();
        assertEquals('P', p2.toBase58().charAt(0));
        assertTrue(p2.isValid());
    }

    @Test
    public void bip47PathDerivatedValidates(){
        DeterministicKey aliceRoot = HDKeyDerivation.createMasterPrivateKey("satoshi lives!".getBytes());
        DeterministicKey alicePurpose = HDKeyDerivation.deriveChildKey(aliceRoot, ChildNumber.BIP47_HARDENED);
        DeterministicKey aliceCoinType = HDKeyDerivation.deriveChildKey(alicePurpose, ChildNumber.ZERO_HARDENED);
        DeterministicKey aliceIdentity = HDKeyDerivation.deriveChildKey(aliceCoinType, ChildNumber.ZERO_HARDENED);
        DeterministicKey aliceNotificationKey = HDKeyDerivation.deriveChildKey(aliceCoinType, ChildNumber.ZERO);
        DeterministicKey aliceNotificationKey2 = HDKeyDerivation.deriveChildKey(aliceCoinType, ChildNumber.ONE);
        PaymentCode alicePaymentCode = new PaymentCodeBuilder().version(1).fromBIP32Key(aliceNotificationKey).build();
        assertTrue(alicePaymentCode.isValid());
        assertNotEquals(new PaymentCodeBuilder().version(1).fromBIP32Key(aliceNotificationKey).build(),
                new PaymentCodeBuilder().version(1).fromBIP32Key(aliceNotificationKey2).build());

        assertEquals(new PaymentCodeBuilder().version(1).fromBIP32Key(aliceIdentity).build(),
                new PaymentCodeBuilder().version(1).fromBIP32Key(aliceIdentity).build());

    }
}
