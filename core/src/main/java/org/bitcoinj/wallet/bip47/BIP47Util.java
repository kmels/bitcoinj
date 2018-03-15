/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;

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

    public static boolean isValidNotificationTransactionOpReturn(TransactionOutput transactionOutput) {
        byte[] data = getOpCodeData(transactionOutput);
        return data != null && HEX.encode(data, 0, 1).equals("01");
    }

    private static byte[] getOpCodeData(TransactionOutput opReturnOutput) {
        List<ScriptChunk> chunks = opReturnOutput.getScriptPubKey().getChunks();
        for (ScriptChunk chunk : chunks) {
            if (!chunk.isOpCode() && chunk.data != null) {
                return chunk.data;
            }
        }
        return null;
    }

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

    public static PaymentAddress getReceiveAddress(Bip47Wallet bip47Wallet, String pcode, int idx) throws AddressFormatException, NotSecp256k1Exception {
        ECKey accountKey = bip47Wallet.getAccount(0).keyAt(idx);
        return getPaymentAddress(bip47Wallet.getNetworkParameters(), new PaymentCode(pcode), 0, accountKey);
    }

    public static PaymentAddress getSendAddress(Bip47Wallet bip47Bip47Wallet, PaymentCode pcode, int idx) throws AddressFormatException, NotSecp256k1Exception {
        ECKey key = bip47Bip47Wallet.getAccount(0).keyAt(0);
        return getPaymentAddress(bip47Bip47Wallet.getNetworkParameters(), pcode, idx, key);
    }

    private static PaymentAddress getPaymentAddress(NetworkParameters networkParameters, PaymentCode pcode, int idx, ECKey key) throws AddressFormatException, NotSecp256k1Exception {
        return new PaymentAddress(networkParameters, pcode, idx, key.getPrivKeyBytes());
    }

    public static String readFromFile(File file) throws IOException {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(file), "UTF8"))) {
            StringBuilder sb = new StringBuilder();

            String newLine = System.lineSeparator();
            String str;
            while ((str = in.readLine()) != null) {
                sb.append(str).append(newLine);
            }
            return sb.toString();
        }
    }

    public static void saveToFile(File file, File temp) throws IOException {
        try (InputStream in = new FileInputStream(temp); OutputStream out = new FileOutputStream(file)) {
            byte[] buf = new byte[1024];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
        }
    }
}
