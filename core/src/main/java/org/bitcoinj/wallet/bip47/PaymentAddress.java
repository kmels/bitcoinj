/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECPoint;

public class PaymentAddress {
    private PaymentCode paymentCode = null;
    private int index = 0;
    private byte[] privKey = null;
    private NetworkParameters networkParameters;
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE;

    public PaymentAddress() {
        this.paymentCode = null;
        this.privKey = null;
        this.index = 0;
    }

    public PaymentAddress(PaymentCode paymentCode) throws AddressFormatException {
        this.paymentCode = paymentCode;
        this.index = 0;
        this.privKey = null;
    }

    public PaymentAddress(NetworkParameters networkParameters, PaymentCode paymentCode, int index, byte[] privKey) throws AddressFormatException {
        this.paymentCode = paymentCode;
        this.index = index;
        this.privKey = privKey;
        this.networkParameters = networkParameters;
    }

    public PaymentCode getPaymentCode() {
        return this.paymentCode;
    }

    public void setPaymentCode(PaymentCode paymentCode) {
        this.paymentCode = paymentCode;
    }

    public int getIndex() {
        return this.index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public byte[] getPrivKey() {
        return this.privKey;
    }

    public void setIndexAndPrivKey(int index, byte[] privKey) {
        this.index = index;
        this.privKey = privKey;
    }

    public void setPrivKey(byte[] privKey) {
        this.privKey = privKey;
    }

    public ECKey getSendECKey() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return this.getSendECKey(this.getSecretPoint());
    }

    public ECKey getReceiveECKey() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return this.getReceiveECKey(this.getSecretPoint());
    }

    public ECPoint get_sG() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return CURVE_PARAMS.getG().multiply(this.getSecretPoint());
    }

    public SecretPoint getSharedSecret() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        return this.sharedSecret();
    }

    public BigInteger getSecretPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return this.secretPoint();
    }

    public ECPoint getECPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        ECKey ecKey = ECKey.fromPublicOnly(this.paymentCode.addressAt(this.networkParameters, this.index).getPubKey());
        return ecKey.getPubKeyPoint();
    }

    public byte[] hashSharedSecret() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(this.getSharedSecret().ECDHSecretAsBytes());
        return hash;
    }

    private ECPoint get_sG(BigInteger s) {
        return CURVE_PARAMS.getG().multiply(s);
    }

    private ECKey getSendECKey(BigInteger s) throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        ECPoint ecPoint = this.getECPoint();
        ECPoint sG = this.get_sG(s);
        ECKey ecKey = ECKey.fromPublicOnly(ecPoint.add(sG).getEncoded(true));
        return ecKey;
    }

    private ECKey getReceiveECKey(BigInteger s) {
        BigInteger privKeyValue = ECKey.fromPrivate(this.privKey).getPrivKey();
        ECKey ecKey = ECKey.fromPrivate(this.addSecp256k1(privKeyValue, s));
        return ecKey;
    }

    private BigInteger addSecp256k1(BigInteger b1, BigInteger b2) {
        BigInteger ret = b1.add(b2);
        return ret.bitLength() > CURVE.getN().bitLength()?ret.mod(CURVE.getN()):ret;
    }

    private SecretPoint sharedSecret() throws AddressFormatException, InvalidKeySpecException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        return new SecretPoint(this.privKey, this.paymentCode.addressAt(this.networkParameters, this.index).getPubKey());
    }

    private boolean isSecp256k1(BigInteger b) {
        return b.compareTo(BigInteger.ONE) > 0 && b.bitLength() <= CURVE.getN().bitLength();
    }

    private BigInteger secretPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NotSecp256k1Exception {
        BigInteger s = new BigInteger(1, this.hashSharedSecret());
        if(!this.isSecp256k1(s)) {
            throw new NotSecp256k1Exception("secret point not on Secp256k1 curve");
        } else {
            return s;
        }
    }

    static {
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    }
}
