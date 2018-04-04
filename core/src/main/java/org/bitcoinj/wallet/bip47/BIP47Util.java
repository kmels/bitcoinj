/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;

import org.bitcoinj.wallet.bip47.Wallet;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.script.ScriptChunk;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
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
    public static PaymentCode getPaymentCodeInNotificationTransaction(byte[] privKeyBytes, Transaction tx) {
        log.debug( "Getting pub key");
        byte[] pubKeyBytes = tx.getInput(0).getScriptSig().getPubKey();

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
            SecretPoint secretPoint = new SecretPoint(privKeyBytes, pubKeyBytes);
            log.debug( "Secret Point: "+ HEX.encode(secretPoint.ECDHSecretAsBytes()));
            log.debug( "Outpoint: "+ HEX.encode(tx.getInput(0).getOutpoint().bitcoinSerialize()));
            log.debug( "Getting mask...");
            byte[] s = PaymentCode.getMask(secretPoint.ECDHSecretAsBytes(), tx.getInput(0).getOutpoint().bitcoinSerialize());
            log.debug( "Getting payload...");
            log.debug( "OpCode Data: "+Utils.HEX.encode(data));
            log.debug( "Mask: "+Utils.HEX.encode(s));
            byte[] payload = PaymentCode.blind(data, s);
            log.debug( "Getting payment code...");
            PaymentCode paymentCode = new PaymentCode(payload);
            log.debug( "Payment Code: "+paymentCode.toString());
            return paymentCode;

        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException | NoSuchFieldError e) {
            e.printStackTrace();
        }
        return null;
    }

    /** Derives the address at idx in the wallet's bip47 account */
    public static PaymentAddress getReceiveAddress(Wallet wallet, String pcode, int idx) throws AddressFormatException, NotSecp256k1Exception {
        ECKey accountKey = wallet.getAccount(0).keyAt(idx);
        return getPaymentAddress(wallet.getNetworkParameters(), new PaymentCode(pcode), 0, accountKey);
    }

    /** Get the address of pcode's owner to send a payment to, using BTC as coin_type */
    public static PaymentAddress getSendAddress(Wallet bip47Wallet, PaymentCode pcode, int idx) throws AddressFormatException, NotSecp256k1Exception {
        ECKey key = bip47Wallet.getAccount(0).keyAt(0);
        return getPaymentAddress(bip47Wallet.getNetworkParameters(), pcode, idx, key);
    }

    /** Creates a PaymentAddress object that the sender will use to pay, using the hardened key at idx */
    private static PaymentAddress getPaymentAddress(NetworkParameters networkParameters, PaymentCode pcode, int idx, ECKey key) throws AddressFormatException, NotSecp256k1Exception {
        return new PaymentAddress(networkParameters, pcode, idx, key.getPrivKeyBytes());
    }
}
