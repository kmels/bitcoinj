package org.bitcoinj.core;

import org.bitcoinj.params.BCCMainNetParams;

public class CopayAddress {
    private Address mAddress;

    public CopayAddress(Address address) {
        mAddress = address;
    }

    public String encode() {
        if (mAddress.getParameters().getId().equals(NetworkParameters.ID_TESTNET)) {

            return Base58.encodeChecked(mAddress.getVersion(), mAddress.getHash());
        } else {
            int version;
            if (mAddress.isP2SHAddress()) {
                version = BCCMainNetParams.COPAY_P2SH_HEADER;
            } else if (mAddress.getVersion() == 0) {
                version = BCCMainNetParams.COPAY_ADDRESS_HEADER;
            } else {
                throw new AddressFormatException("Wrong version");
            }

            return Base58.encodeChecked(version, mAddress.getHash());
        }
    }

    public static Address decode(NetworkParameters params, String address) {
        Address addr = Address.fromString(params, address);
        if (params.getId().equals(NetworkParameters.ID_TESTNET)) {
            return addr;
        } else {
            int version;
            if (addr.getVersion() == BCCMainNetParams.COPAY_ADDRESS_HEADER) {
                version = params.addressHeader;
            } else if (addr.getVersion() == BCCMainNetParams.COPAY_P2SH_HEADER) {
                version = params.p2shHeader;
            } else {
                throw new AddressFormatException("Wrong version");
            }

            if (version == params.getAddressHeader())
                return new LegacyAddress(params, false, addr.getHash());
            else if (version == params.getP2SHHeader())
                return new LegacyAddress(params, true, addr.getHash());
            throw new AddressFormatException.WrongNetwork(version);
        }
    }
}
