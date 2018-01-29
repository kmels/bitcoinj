package org.bitcoinj.wallet.bip47;

import org.bitcoinj.core.Utils;

import static com.google.common.base.Preconditions.checkArgument;

/*
    A payment code contains the following elements:

    Byte 0: version. required value: 0x01
    Byte 1: features bit field. All bits must be zero except where specified elsewhere in this specification
    Bit 0: Bitmessage notification
    Bits 1-7: reserved
    Byte 2: sign. required value: 0x02 or 0x03
    Bytes 3 - 34: x value, must be a member of the secp256k1 group
    Bytes 35 - 66: chain code
    Bytes 67 - 79: reserved for future expansion, zero-filled unless otherwise noted
 */
public class PaymentCodeBuilder {
    private byte[] bytes;

    /** Creates a PaymentCodeBuilder with an empty payload*/
    public PaymentCodeBuilder() {
        bytes = new byte[80];
    }

    /** Creates a PaymentCodeBuilder with the given version and an empty payload */
    public PaymentCodeBuilder version(int version) {
        bytes[0] = (byte) version;
        bytes[1] = (byte) 0x00;
        return this;
    }

    public PaymentCodeBuilder pubKey(byte[] pubkey) {
        checkArgument(pubkey.length==33, "Expected a pubKey of length 32");
        checkArgument(pubkey[0]==0x02 || pubkey[0]==0x03, "Expected the first byte of pubKey "+
                Utils.HEX.encode(pubkey)+") to be 0x02 or 0x03. ");
        // set bytes 2 - 34
        System.arraycopy(pubkey, 0, bytes, 2, pubkey.length);
        return this;
    }

    public PaymentCodeBuilder chainCode(byte[] chainCode) {
        checkArgument(chainCode.length==32, "Expected a pubKey of length 32");
        System.arraycopy(chainCode, 0, bytes, 35, chainCode.length);
        return this;
    }

    public PaymentCode build(){
        return new PaymentCode(bytes);
    }
}
