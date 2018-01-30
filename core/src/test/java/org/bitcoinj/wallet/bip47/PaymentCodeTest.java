package org.bitcoinj.wallet.bip47;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.crypto.*;
import org.junit.Assert;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.util.List;

import static org.bitcoinj.core.Utils.HEX;
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

    @Test
    public void isBase58CheckedWorking(){
        String P = "PM8TJaWSfZYLLuJnXctJ8npNYrUr5UCeT6KGmayJ4ENDSqj7VZr7uyX9exCo5JA8mFLkeXPaHoCBKuMDpYFs3tdxP2UxNiHSsZtb1KkKSVQyiwFhdLTZ";
        PaymentCode p = new PaymentCodeBuilder().fromBase58Checked(P).build();
        assertEquals(p.toBase58(), P);
    }

    @Test
    public void myOwnPaymentCodeIsValidates(){
        String P = "PM8TJaWSfZYLLuJnXctJ8npNYrUr5UCeT6KGmayJ4ENDSqj7VZr7uyX9exCo5JA8mFLkeXPaHoCBKuMDpYFs3tdxP2UxNiHSsZtb1KkKSVQyiwFhdLTZ";
        PaymentCode p = new PaymentCodeBuilder().fromBase58Checked(P).build();
        assertTrue(p.isValid());
    }

    @Test
    public void hexPaymentCodeValidates(){
        String P = "010003a32596cd836ac88ad53c087253f7bafd080902fbf36eef5809c3a553411f0d55a843966e5aa48de7c4de3c18023e480c4b2f2a25be31489219d32b4def03ab1500000000000000000000000000";
        PaymentCode p = new PaymentCode(Hex.decode(P));
        assertTrue(p.isValid());
    }
}
