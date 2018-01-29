package org.bitcoinj.wallet.bip47;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.VersionedChecksummedBytes;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;

import java.nio.ByteBuffer;
import java.util.Arrays;

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
public class PaymentCode {
    private static final int LENGTH = 80;
    byte[] payload = new byte[LENGTH];

    public PaymentCode(byte[] payload)    {
        if(payload.length != LENGTH)  {
            return;
        }
        this.payload = payload;
    }

    public String toBase58(){
        VersionedChecksummedBytes address = new VersionedChecksummedBytes((int) 0x47, payload);
        return address.toBase58();
    }

    public DeterministicKey makeMasterPubKey(){
        return HDKeyDerivation.createMasterPubKeyFromBytes(Arrays.copyOfRange(payload, 2, 35), Arrays.copyOfRange(payload, 35, 67));
    }

    public boolean isValid(){
        byte[] decodedBytes = Base58.decodeChecked(this.toBase58());

        ByteBuffer byteBuffer = ByteBuffer.wrap(decodedBytes);
        if(byteBuffer.get() != 0x47)   {
            throw new AddressFormatException("invalid version: " + this.toBase58());
        }
        if (decodedBytes[3] == 0x02 || decodedBytes[3] == 0x03)
            return true;

        return false;
    }

    @Override
    public String toString(){
        return this.toBase58();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Arrays.equals(payload, ((PaymentCode)o).payload);
    }
}

