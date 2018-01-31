//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.bitcoinj.crypto.bip47;

import java.math.BigInteger;
import org.apache.commons.lang3.ArrayUtils;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;

public class Address {
    private int childNum;
    private String strPath = null;
    private ECKey ecKey = null;
    private byte[] pubKey = null;
    private byte[] pubKeyHash = null;
    private NetworkParameters params = null;

    private Address() {
    }

    public Address(NetworkParameters params, DeterministicKey cKey, int child) {
        this.params = params;
        this.childNum = child;
        DeterministicKey dk = HDKeyDerivation.deriveChildKey(cKey, new ChildNumber(this.childNum, false));
        if(dk.hasPrivKey()) {
            byte[] now = ArrayUtils.addAll(new byte[1], dk.getPrivKeyBytes());
            this.ecKey = ECKey.fromPrivate(new BigInteger(now), true);
        } else {
            this.ecKey = ECKey.fromPublicOnly(dk.getPubKey());
        }

        long now1 = Utils.now().getTime() / 1000L;
        this.ecKey.setCreationTimeSeconds(now1);
        this.pubKey = this.ecKey.getPubKey();
        this.pubKeyHash = this.ecKey.getPubKeyHash();
        this.strPath = dk.getPathAsString();
    }

    public byte[] getPubKey() {
        return this.pubKey;
    }

    public byte[] getPubKeyHash() {
        return this.pubKeyHash;
    }

    public String getAddressString() {
        return this.ecKey.toAddress(this.params).toString();
    }

    public String getPrivateKeyString() {
        return this.ecKey.hasPrivKey()?this.ecKey.getPrivateKeyEncoded(this.params).toString():null;
    }

    public org.bitcoinj.core.Address getAddress() {
        return this.ecKey.toAddress(this.params);
    }

    public String getPath() {
        return this.strPath;
    }

    /*STASH:FIXME*/
    /*public JSONObject toJSON() {
        try {
            JSONObject ex = new JSONObject();
            ex.put("address", this.getAddressString());
            if(this.ecKey.hasPrivKey()) {
                ex.put("key", this.getPrivateKeyString());
            }

            ex.put("path", this.getPath());
            return ex;
        } catch (JSONException var2) {
            throw new RuntimeException(var2);
        }
    }*/
}
