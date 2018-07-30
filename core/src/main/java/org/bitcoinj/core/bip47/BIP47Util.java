/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.core.bip47;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.BIP47SecretPoint;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.kits.BIP47AppKit;
import org.bitcoinj.script.ScriptPattern;
import org.bitcoinj.wallet.bip47.NotSecp256k1Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

import static org.bitcoinj.core.Utils.HEX;

/**
 * Created by jimmy on 9/29/17.
 */

public class BIP47Util {
    private static final Logger log = LoggerFactory.getLogger(BIP47Util.class);

    /**
     * Finds the first output in a transaction whose op code is OP_RETURN.
     */
    @Nullable
    public static TransactionOutput getOpCodeOutput(Transaction tx) {
        List<TransactionOutput> outputs = tx.getOutputs();
        for (TransactionOutput o : outputs) {
            if (o.getScriptPubKey().isOpReturn()) {
                return o;
            }
        }
        return null;
    }

    /** Returns true if the OP_RETURN op code begins with the byte 0x01 (version 1), */
    public static boolean isValidNotificationTransactionOpReturn(TransactionOutput transactionOutput) {
        byte[] data = getOpCodeData(transactionOutput);
        return data != null && HEX.encode(data, 0, 1).equals("01");
    }

    /** Return the payload of the first op code e.g. OP_RETURN. */
    private static byte[] getOpCodeData(TransactionOutput opReturnOutput) {
        List<ScriptChunk> chunks = opReturnOutput.getScriptPubKey().getChunks();
        for (ScriptChunk chunk : chunks) {
            if (!chunk.isOpCode() && chunk.data != null) {
                return chunk.data;
            }
        }
        return null;
    }

    /* Extract the payment code from an incoming notification transaction */
    public static BIP47PaymentCode getPaymentCodeInNotificationTransaction(byte[] privKeyBytes, Transaction tx) {
        log.debug( "Getting pub key");
        Script sigScript = tx.getInput(0).getScriptSig();
        if (!ScriptPattern.isPayToPubKey(sigScript)) {
            return null;
        }
        byte[] pubKeyBytes = ScriptPattern.extractKeyFromPayToPubKey(sigScript);

        log.debug( "Private Key: "+ Utils.HEX.encode(privKeyBytes));
        log.debug( "Public Key: "+Utils.HEX.encode(pubKeyBytes));

        log.debug( "Getting op_code data");
        TransactionOutput opReturnOutput = getOpCodeOutput(tx);
        if (opReturnOutput == null) {
            return null;
        }
        byte[] data = getOpCodeData(opReturnOutput);

        try {
            log.debug( "Getting secret point..");
            BIP47SecretPoint BIP47SecretPoint = new BIP47SecretPoint(privKeyBytes, pubKeyBytes);
            log.debug( "Secret Point: "+ HEX.encode(BIP47SecretPoint.ECDHSecretAsBytes()));
            log.debug( "Outpoint: "+ HEX.encode(tx.getInput(0).getOutpoint().bitcoinSerialize()));
            log.debug( "Getting mask...");
            byte[] s = BIP47PaymentCode.getMask(BIP47SecretPoint.ECDHSecretAsBytes(), tx.getInput(0).getOutpoint().bitcoinSerialize());
            log.debug( "Getting payload...");
            log.debug( "OpCode Data: "+Utils.HEX.encode(data));
            log.debug( "Mask: "+Utils.HEX.encode(s));
            byte[] payload = BIP47PaymentCode.blind(data, s);
            log.debug( "Getting payment code...");
            BIP47PaymentCode BIP47PaymentCode = new BIP47PaymentCode(payload);
            log.debug( "Payment Code: "+ BIP47PaymentCode.toString());
            return BIP47PaymentCode;

        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException | NoSuchFieldError e) {
            e.printStackTrace();
        }
        return null;
    }

    /** Derives the receive address at idx in depositWallet for senderPaymentCode to deposit, in the wallet's bip47 0th account, i.e. <pre>m / 47' / coin_type' / 0' / idx' .</pre>. */
    public static BIP47PaymentAddress getReceiveAddress(BIP47AppKit depositWallet, String senderPaymentCode, int idx) throws AddressFormatException, NotSecp256k1Exception {
        ECKey accountKey = depositWallet.getAccount(0).keyAt(idx);
        return getPaymentAddress(depositWallet.getParams(), new BIP47PaymentCode(senderPaymentCode), 0, accountKey);
    }

    /** Get the address of receiverBIP47PaymentCode's owner to send a payment to, using BTC as coin_type */
    public static BIP47PaymentAddress getSendAddress(BIP47AppKit spendWallet, BIP47PaymentCode receiverBIP47PaymentCode, int idx) throws AddressFormatException, NotSecp256k1Exception {
        ECKey key = spendWallet.getAccount(0).keyAt(0);
        return getPaymentAddress(spendWallet.getParams(), receiverBIP47PaymentCode, idx, key);
    }

    /** Creates a BIP47PaymentAddress object that the sender will use to pay, using the hardened key at idx */
    private static BIP47PaymentAddress getPaymentAddress(NetworkParameters networkParameters, BIP47PaymentCode pcode, int idx, ECKey key) throws AddressFormatException, NotSecp256k1Exception {
        return new BIP47PaymentAddress(networkParameters, pcode, idx, key.getPrivKeyBytes());
    }
}
