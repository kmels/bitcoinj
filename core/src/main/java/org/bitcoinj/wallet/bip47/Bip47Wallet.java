/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;


import com.google.common.base.Joiner;
import com.google.common.net.InetAddresses;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.bitcoinj.crypto.bip47.Bip47Account;
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.*;
import org.bitcoinj.wallet.bip47.listeners.BlockchainDownloadProgressTracker;
import org.bitcoinj.wallet.bip47.listeners.TransactionEventListener;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.CashAddress;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.bitcoinj.core.Utils.HEX;
import static org.bitcoinj.core.Utils.join;

/**
 * Created by jimmy on 9/28/17.
 */

/**
 * <p>A {@link Bip47Wallet} that runs in SPV mode and supports BIP 47 payments for coins BTC, BCH, tBTC and tBCH. You will
 * need to instantiate one wallet per supported coin.</p>
 *
 * <p>It produces two files in a designated directory. The directory name is the coin name. and is created in workingDirectory: </p>
 * <ul>
 *     <il>The .spvchain (blockstore): maintains a maximum # of headers mapped to memory (5000)</il>
 *     <il>The .wallet: stores the wallet with txs, can be encrypted, storing keys</il>
 * </ul>
 *
 * <p>By calling {@link Bip47Wallet.start()}, this wallet will automatically import payment addresses when a Bip 47
 * notification transaction is received.</p>
 *
 */

public class Bip47Wallet extends org.bitcoinj.wallet.Wallet {
    // the blokstore is used by a blockchain as a memory data structure
    private volatile BlockChain vChain;
    private volatile BlockStore vStore;
    // the blockchain is used by the peergroup
    private volatile PeerGroup vPeerGroup;
    // the directory will have the spvchain and the wallet files
    private volatile File directory;
    private volatile File walletFile;
    // the coin name that this wallet supports. Can be: BTC, tBTC, BCH, tBCH
    private String coinName;
    // Wether this wallet is restored from a BIP39 seed and will need to replay the complete blockchain
    // Will be null if it's not a restored wallet.
    private DeterministicSeed restoreFromSeed;

    // Support for BIP47-type accounts. Only one account is currently handled in this wallet.
    private List<Bip47Account> mBip47Accounts = new ArrayList<>(1);

    // The progress tracker will callback the listener with a porcetage of the blockchain that it has downloaded, while downloading..
    private BlockchainDownloadProgressTracker mBlockchainDownloadProgressTracker = null;

    // This wallet allows one listener to be invoked when there are coins received and
    private TransactionEventListener mCoinsReceivedEventListener = null;
    // one listener when the transaction confidence changes
    private TransactionEventListener mTransactionConfidenceListener = null;

    // The payment channels indexed by payment codes.
    // A payment channel is created and saved if:
    //   - someone sends a notification transaction to this wallet's notifiction address
    //   - this wallet creates a notification transaction to a payment channel.
    //
    // It doesn't check if the notification transactions are mined before adding a payment code.
    // If you want to know a transaction's confidence, see #{@link Transaction.getConfidence()}

    private ConcurrentHashMap<String, Bip47PaymentChannel> channels = new ConcurrentHashMap<>();
    // create a logger
    private static final Logger log = LoggerFactory.getLogger(Bip47Wallet.class);


    /**
     * Creates a new wallet for a coinName, the .spvchain and .wallet files in workingDir/coinName.
     *
     * Any keys will be derived from deterministicSeed.
     */
    public Bip47Wallet(NetworkParameters params, File workingDir, String coinName, @Nullable DeterministicSeed deterministicSeed) throws Exception {
        super(params);

        this.directory = new File(workingDir, coinName);

        // ensure directory exists
        if (!this.directory.exists()) {
            if (!this.directory.mkdirs()) {
                throw new IOException("Could not create directory " + directory.getAbsolutePath());
            }
        }

        this.coinName = coinName;
        this.restoreFromSeed = deterministicSeed;

        // point to the file with the serialized Wallet
        File walletFile = new File(directory, coinName + ".wallet");
        // if there is a serialized Wallet and an initiated chain file,
        boolean chainFileExists = getChainFile().exists();

        // replay the wallet if deterministicSeed is defined or the chain file is deleted
        // as a trigger of the wallet user to replay it
        boolean shouldReplayWallet = (walletFile.exists() && !chainFileExists) || deterministicSeed != null;
        //Context.propagate(new Context(params));

        // use a Wallet reader
        // TODO: We should use WalletExtension's serialization to read, write and import this wallet's properties
        org.bitcoinj.wallet.Wallet coreWallet;

        // if coinName/coinName.wallet exists, we load it as a core Wallet and then manually set each of the bip47 properties
        if (walletFile.exists()) {
            coreWallet = load(params, shouldReplayWallet, walletFile);
        } else {
            // create an empty wallet
            coreWallet = create(params);
            // with a seed
            coreWallet.freshReceiveKey();
            // reload the wallet
            coreWallet.saveToFile(walletFile);
            String mnemonic = join(coreWallet.getKeyChainSeed().getMnemonicCode());
            coreWallet = load(params, false, walletFile);
            String mnemonic2 = join(coreWallet.getKeyChainSeed().getMnemonicCode());
        }

        String seedb = HEX.encode(coreWallet.getKeyChainSeed().getSeedBytes());
        // every 5 seconds let's persist the transactions, keys, last block height, watched scripts, etc.
        // does not persist channels recurrently, instead payment channels are currently saved in a separete file (.bip47 extension).
        autosaveToFile(walletFile, 5, TimeUnit.SECONDS, null);

        // add to this wallet all the core Wallet's properties. This code should be removed after channels are implemented as WalletExtension.
        //   - watched scripts
        addWatchedScripts(coreWallet.getWatchedScripts());
        if (coreWallet.getDescription() != null) {
            setDescription(coreWallet.getDescription());
        }

        if (shouldReplayWallet) {
            // Should mirror Wallet.reset()
            setLastBlockSeenHash(null);
            setLastBlockSeenHeight(-1);
            setLastBlockSeenTimeSecs(0);
        } else {
            // last block state
            setLastBlockSeenHash(coreWallet.getLastBlockSeenHash());
            setLastBlockSeenHeight(coreWallet.getLastBlockSeenHeight());
            setLastBlockSeenTimeSecs(coreWallet.getLastBlockSeenTimeSecs());

            // transaction outputs to point to inputs that spend them
            Iterator<WalletTransaction> iter = coreWallet.getWalletTransactions().iterator();
            while(iter.hasNext())
                addWalletTransaction(iter.next());

            // timestamp to use as a starting point to possibly invalidate keys created before this time
            if (coreWallet.getKeyRotationTime() != null)
                setKeyRotationTime(coreWallet.getKeyRotationTime());
        }

        //todo: load bip47meta wallet extension
        //loadExtensions(wallet, extensions != null ? extensions : new WalletExtension[0], walletProto);

        this.tags = coreWallet.getTags();

        //  - add the saved input signers for future output spends
        for (TransactionSigner signer : coreWallet.getTransactionSigners()) {
            addTransactionSigner(signer);
        }

        setVersion(coreWallet.getVersion());

        // create a bip47 account, i.e. derive the key M/47'/0'/0'
        String seed = HEX.encode(getKeyChainSeed().getSeedBytes());
        byte[] hd_seed = this.restoreFromSeed != null ?
                this.restoreFromSeed.getSeedBytes() :
                coreWallet.getKeyChainSeed().getSeedBytes();

        deriveAccount(hd_seed);

        Address notificationAddress = mBip47Accounts.get(0).getNotificationAddress();
        log.debug("Wallet notification address: "+notificationAddress.toString());

        if (!coreWallet.isAddressWatched(notificationAddress)) {
            addWatchedAddress(notificationAddress);
        }

        allowSpendingUnconfirmedTransactions();

        // init
        File chainFile = getChainFile();

        // open the blockstore file
        vStore = new SPVBlockStore(params, chainFile);
        // create a fresh blockstore file before restoring a wallet
        if (restoreFromSeed != null && chainFileExists) {
            log.info( "Deleting the chain file in preparation from restore.");
            vStore.close();
            if (!chainFile.delete())
                log.warn("start: ", new IOException("Failed to delete chain file in preparation for restore."));
            vStore = new SPVBlockStore(params, chainFile);
        }

        try {
            // create the blockchain object using the file-backed blockstore
            vChain = new BlockChain(params, vStore);
        } catch (BlockStoreException e){
            // we can create a new blockstore in case the file is corrupted, the wallet should have a last height
            if (chainFile.exists()) {
                log.warn("deleteSpvFile: exists but it is corrupted");
                chainFile.delete();
            }
            vStore = new SPVBlockStore(params, chainFile);
            vChain = new BlockChain(params, vStore);
        }

        // create peergroup for the blockchain
        vPeerGroup = new PeerGroup(params, vChain);

        // add Stash-Crypto dedicated nodes for bitcoincash
        if (getCoinName().equals("BCH")) {
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("158.69.119.35"), 8333));
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("144.217.73.86"), 8333));
        } else if (getCoinName().equals("tBCH")) {
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("158.69.119.35"), 8333));
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("144.217.73.86"), 18333));
        }

        // connect to peer running in localhost
        vPeerGroup.setUseLocalhostPeerWhenPossible(true);
        // connect to peers in the coinName network
        vPeerGroup.addPeerDiscovery(new DnsDiscovery(params));

        // add the wallet so that syncing and rolling the chain can affect this wallet
        vChain.addWallet(this);
        // add the wallet to the peers so that every peer listener can find this wallet
        vPeerGroup.addWallet(this);

        // Bip47-specific listener
        // When a new *notification* transaction is received:
        //  - new keys are generated and imported for incoming payments in the bip47 account/contact payment channel
        //  - the chain is rolled back 2 blocks so that payment transactions are not missed if in the same block as the notification transaction.
        //
        // When a new *payment* transaction is received:
        //  - a new key is generated and imported to the wallet

        this.addOnReceiveTransactionListener(new TransactionEventListener() {
            @Override
            public void onTransactionReceived(Bip47Wallet bip47Wallet, Transaction transaction) {

                if (isNotificationTransaction(transaction)) {
                    log.debug("Valid notification transaction received");
                    PaymentCode paymentCode = getPaymentCodeInNotificationTransaction(transaction);
                    if (paymentCode == null) {
                        log.warn("Error decoding payment code in tx {}", transaction);
                    } else {
                        log.debug("Payment Code: " + paymentCode);
                        boolean needsSaving = savePaymentCode(paymentCode);
                        if (needsSaving) {
                            saveBip47PaymentChannelData();
                        }
                    }
                } else if (isToBIP47Address(transaction)) {
                    log.debug("New BIP47 payment received to address: "+getAddressOfReceived(transaction));
                    boolean needsSaving = generateNewBip47IncomingAddress(getAddressOfReceived(transaction).toString());
                    if (needsSaving) {
                        saveBip47PaymentChannelData();
                    }
                    String paymentCode = getPaymentCodeForAddress(getAddressOfReceived(transaction).toString());
                    log.debug("Received tx for Payment Code: " + paymentCode);
                } else {
                    Coin valueSentToMe = getValueSentToMe(transaction);
                    log.debug("Received tx for "+valueSentToMe.toFriendlyString() + ":" + transaction);
                }
            }

            @Override
            public void onTransactionConfidenceEvent(Bip47Wallet bip47Wallet, Transaction transaction) {
                return;
            }
        });
        log.debug("Created wallet: " +toString());
    }

    public Bip47Wallet(NetworkParameters params, KeyChainGroup kcg){
        super(params, kcg);
    }

    // Return the wallet's SPVChain
    protected File getChainFile(){
        return new File(directory, getCoinName() + ".spvchain");
    }

    // Load an offline wallet from a file and return a @{link org.bitcoinj.wallet.Wallet}.
    // If shouldReplayWallet is false, the wallet last block is reset to -1
    public static org.bitcoinj.wallet.Wallet load(NetworkParameters networkParameters, boolean shouldReplayWallet, File vWalletFile) throws Exception {
        try (FileInputStream walletStream = new FileInputStream(vWalletFile)) {
            Protos.Wallet proto = WalletProtobufSerializer.parseToProto(walletStream);
            final WalletProtobufSerializer serializer = new WalletProtobufSerializer();
            org.bitcoinj.wallet.Wallet wallet = serializer.readWallet(networkParameters, null, proto);
            String walletSeed = HEX.encode(wallet.getKeyChainSeed().getSeedBytes());
            String walletMnemonic = join(wallet.getKeyChainSeed().getMnemonicCode());
            if (shouldReplayWallet)
                wallet.reset();
            return wallet;
        }
    }

    private Bip47Wallet create(NetworkParameters networkParameters) throws IOException {
        KeyChainGroup kcg;
        if (restoreFromSeed != null)
            kcg = new KeyChainGroup(networkParameters, restoreFromSeed);
        else
            kcg = new KeyChainGroup(networkParameters);
        return new Bip47Wallet(networkParameters, kcg);  // default
    }

    public String getCoinName() {
        return this.coinName;
    }

    /**
     * <p>Create the account M/47'/0'/0' from the seed as a Bip47Account.</p>
     *
     * <p>After deriving, this wallet's payment code is available in @{link Bip47Wallet.getPaymentCode()}</p>
     */
    public void deriveAccount(byte[] hd_seed) {
        String seed = HEX.encode(hd_seed);
        DeterministicKey mKey = HDKeyDerivation.createMasterPrivateKey(hd_seed);
        DeterministicKey purposeKey = HDKeyDerivation.deriveChildKey(mKey, 47 | ChildNumber.HARDENED_BIT);
        DeterministicKey coinKey = HDKeyDerivation.deriveChildKey(purposeKey, ChildNumber.HARDENED_BIT);
        Bip47Account bip47Account = new Bip47Account(this.params, coinKey, 0);

        mBip47Accounts.clear();
        mBip47Accounts.add(bip47Account);
    }

    /*
     * <p>Connect this wallet to the network. Watch notification and payment transactions.</p>
     */
    public void startBlockchainDownload() {
        if (!vPeerGroup.isRunning()) {
            log.debug("Starting blockchain download.");
            vPeerGroup.start();
            vPeerGroup.startBlockChainDownload(mBlockchainDownloadProgressTracker);
        } else
            log.warn("Not starting ... blockchain download is already started.");
    }

    public List<Peer> getConnectedPeers() {
        return vPeerGroup.getConnectedPeers();
    }

    /**
     * Disconnects the wallet from the network
     */
    public void stop() {
        if (vPeerGroup == null || !isStarted()) {
            return;
        }

        log.debug("Stopping peergroup");
        if (vPeerGroup.isRunning()) vPeerGroup.stopAsync();
        try {
            log.debug("Saving wallet");
            saveToFile(walletFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        log.debug("stopWallet: closing store");
        try {
            vStore.close();
        } catch (BlockStoreException e) {
            e.printStackTrace();
        }

        vStore = null;

        log.debug("stopWallet: Done");
    }

    public boolean isStarted() {
        return vPeerGroup.isRunning();
    }

    public void setBlockchainDownloadProgressTracker(BlockchainDownloadProgressTracker downloadProgressTracker) {
        mBlockchainDownloadProgressTracker = downloadProgressTracker;
    }

    /**
     * <p>Reads the channels from .bip47 file. Return true if any payment code was loaded. </p>
     */
    public boolean loadBip47PaymentChannelData() {
        String jsonString = readBip47PaymentChannelDataFile();

        if (StringUtils.isEmpty(jsonString)) {
            return false;
        }

        log.debug("loadBip47PaymentChannelData: "+jsonString);

        return importBip47PaymentChannelData(jsonString);
    }

    /**
     * <p>Reads the channels from .bip47 file. Return true if any payment code was loaded. </p>
     */
    public String readBip47PaymentChannelDataFile() {
        File file = new File(directory, getCoinName().concat(".bip47"));
        String jsonString;
        try {
            jsonString = FileUtils.readFileToString(file, Charset.defaultCharset());
        } catch (IOException e){
            log.debug("Creating BIP47 wallet file at " + file.getAbsolutePath() + "  ...");
            saveBip47PaymentChannelData();
            loadBip47PaymentChannelData();
            return null;
        }

        return jsonString;
    }

    /**
     * <p>Load channels from json. Return true if any payment code was loaded. </p>
     */
    public boolean importBip47PaymentChannelData(String jsonString) {
        log.debug("loadBip47PaymentChannelData: "+jsonString);

        Gson gson = new Gson();
        Type collectionType = new TypeToken<Collection<Bip47PaymentChannel>>(){}.getType();
        try {
            List<Bip47PaymentChannel> Bip47PaymentChannelList = gson.fromJson(jsonString, collectionType);
            if (Bip47PaymentChannelList != null) {
                for (Bip47PaymentChannel paymentChannel: Bip47PaymentChannelList) {
                    channels.put(paymentChannel.getPaymentCode(), paymentChannel);
                }
                return true;
            }
        } catch (JsonSyntaxException e) {
        }
        return false;
    }

    /**
     * <p>Persists the .bip47 file with the channels. </p>
     */
    public synchronized void saveBip47PaymentChannelData() {
        try {
            saveToFile(walletFile);
        } catch (IOException io){
            log.error("Failed to save wallet file",io);
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(channels.values());

        log.debug("saveBip47PaymentChannelData: "+json);

        File file = new File(directory, getCoinName().concat(".bip47"));

        try {
            FileUtils.writeStringToFile(file, json, Charset.defaultCharset(), false);
            log.debug("saveBip47PaymentChannelData: saved");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /** <p>Persists the .bip47 file with the channels. </p> */
    public void addOnReceiveTransactionListener(TransactionEventListener transactionEventListener){
        if (this.mCoinsReceivedEventListener != null)
            this.removeCoinsReceivedEventListener(mCoinsReceivedEventListener);

        transactionEventListener.setBip47Wallet(this);
        this.addCoinsReceivedEventListener(transactionEventListener);

        mCoinsReceivedEventListener = transactionEventListener;
    }

    /** <p>Persists the .bip47 file with the channels. </p> */
    public void addTransactionConfidenceEventListener(TransactionEventListener transactionEventListener){
        if (this.mTransactionConfidenceListener != null)
            this.removeTransactionConfidenceEventListener(mTransactionConfidenceListener);

        transactionEventListener.setBip47Wallet(this);
        this.addTransactionConfidenceEventListener(transactionEventListener);

        mTransactionConfidenceListener = transactionEventListener;
    }

    /** <p> Retrieve the relevant address (P2PKH or P2PSH) and compares it with the notification address of this wallet. </p> */
    public boolean isNotificationTransaction(Transaction tx) {
        Address address = getAddressOfReceived(tx);
        Address myNotificationAddress = mBip47Accounts.get(0).getNotificationAddress();

        return address != null && address.toString().equals(myNotificationAddress.toString());
    }

    /** <p> Retrieve the relevant address (P2PKH or P2PSH), return true if any key in this wallet translates to it. </p> */
    // TODO: return true if and only if it is a channel address.
    public boolean isToBIP47Address(Transaction transaction) {
        List<ECKey> keys = getImportedKeys();
        for (ECKey key : keys) {
            Address address = key.toAddress(getNetworkParameters());
            if (address == null) {
                continue;
            }
            Address addressOfReceived = getAddressOfReceived(transaction);
            if (addressOfReceived != null && address.toString().equals(addressOfReceived.toString())) {
                return true;
            }
        }
        return false;
    }

    public Address getAddressOfReceived(Transaction tx) {
        for (final TransactionOutput output : tx.getOutputs()) {
            try {
                if (output.isMineOrWatched(this)) {
                    final Script script = output.getScriptPubKey();
                    return script.getToAddress(getNetworkParameters(), true);
                }
            } catch (final ScriptException x) {
                // swallow
            }
        }

        return null;
    }

    public Address getAddressOfSent(Transaction tx) {
        for (final TransactionOutput output : tx.getOutputs()) {
            try {
                if (!output.isMineOrWatched(this)) {
                    final Script script = output.getScriptPubKey();
                    return script.getToAddress(getNetworkParameters(), true);
                }
            } catch (final ScriptException x) {
                // swallow
            }
        }

        return null;
    }

    public PaymentCode getPaymentCodeInNotificationTransaction(Transaction tx) {
        byte[] privKeyBytes = mBip47Accounts.get(0).getNotificationKey().getPrivKeyBytes();

        return BIP47Util.getPaymentCodeInNotificationTransaction(privKeyBytes, tx);
    }

    // <p> Receives a payment code and returns true iff there is already an incoming address generated for the channel</p>
    public boolean savePaymentCode(PaymentCode paymentCode) {
        if (channels.containsKey(paymentCode.toString())) {
            Bip47PaymentChannel paymentChannel = channels.get(paymentCode.toString());
            if (paymentChannel.getIncomingAddresses().size() != 0) {
                return false;
            } else {
                try {
                    paymentChannel.generateKeys(this);
                    return true;
                } catch (NotSecp256k1Exception | InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
                    e.printStackTrace();
                    return false;
                }
            }
        }

        Bip47PaymentChannel paymentChannel  = new Bip47PaymentChannel(paymentCode.toString());

        try {
            paymentChannel.generateKeys(this);
            channels.put(paymentCode.toString(), paymentChannel);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public Bip47Account getAccount(int i) {
        return mBip47Accounts.get(i);
    }

    public Address getAddressOfKey(ECKey key) {
        return key.toAddress(getNetworkParameters());
    }

    public boolean generateNewBip47IncomingAddress(String address) {
        for (Bip47PaymentChannel paymentChannel  : channels.values()) {
            for (Bip47Address bip47Address : paymentChannel.getIncomingAddresses()) {
                if (!bip47Address.getAddress().equals(address)) {
                    continue;
                }
                if (bip47Address.isSeen()) {
                    return false;
                }

                int nextIndex = paymentChannel.getCurrentIncomingIndex() + 1;
                try {
                    ECKey key = BIP47Util.getReceiveAddress(this, paymentChannel.getPaymentCode(), nextIndex).getReceiveECKey();
                    importKey(key);
                    Address newAddress = getAddressOfKey(key);
                    paymentChannel.addNewIncomingAddress(newAddress.toString(), nextIndex);
                    bip47Address.setSeen(true);
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return false;
            }
        }
        return false;
    }

    public Bip47PaymentChannel getBip47PaymentChannelForAddress(String address) {
        for (Bip47PaymentChannel paymentChannel  : channels.values()) {
            for (Bip47Address bip47Address : paymentChannel.getIncomingAddresses()) {
                if (bip47Address.getAddress().equals(address)) {
                    return paymentChannel;
                }
            }
        }
        return null;
    }

    public String getPaymentCodeForAddress(String address) {
        for (Bip47PaymentChannel paymentChannel  : channels.values()) {
            for (Bip47Address bip47Address : paymentChannel.getIncomingAddresses()) {
                if (bip47Address.getAddress().equals(address)) {
                    return paymentChannel.getPaymentCode();
                }
            }
        }
        return null;
    }

    public Bip47PaymentChannel getBip47PaymentChannelForOutgoingAddress(String address) {
        for (Bip47PaymentChannel paymentChannel  : channels.values()) {
            for (String outgoingAddress : paymentChannel.getOutgoingAddresses()) {
                if (outgoingAddress.equals(address)) {
                    return paymentChannel;
                }
            }
        }
        return null;
    }

    public Bip47PaymentChannel getBip47PaymentChannelForPaymentCode(String paymentCode) {
        for (Bip47PaymentChannel paymentChannel  : channels.values()) {
            if (paymentChannel.getPaymentCode().equals(paymentCode)) {
                return paymentChannel;
            }
        }
        return null;
    }

    public Coin getValueOfTransaction(Transaction transaction) {
        return transaction.getValue(this);
    }

    public Coin getValueSentToMe(Transaction transaction) {
        return transaction.getValueSentToMe(this);
    }

    public Coin getValueSentFromMe(Transaction transaction) {
        return transaction.getValueSentFromMe(this);
    }

    public List<Transaction> getTransactions() {
        return getTransactionsByTime();
    }

    public long getBalanceValue() {
        return getBalance(org.bitcoinj.wallet.Wallet.BalanceType.ESTIMATED_SPENDABLE).getValue();
    }

    public Coin getBalance() {
        return getBalance(org.bitcoinj.wallet.Wallet.BalanceType.ESTIMATED_SPENDABLE);
    }

    public boolean isDownloading() {
        return mBlockchainDownloadProgressTracker != null && mBlockchainDownloadProgressTracker.isDownloading();
    }

    public double getBlockchainProgress() {
        return mBlockchainDownloadProgressTracker != null ? mBlockchainDownloadProgressTracker.getProgress() : -1d;
    }

    public boolean isTransactionEntirelySelf(Transaction tx) {
        for (final TransactionInput input : tx.getInputs()) {
            final TransactionOutput connectedOutput = input.getConnectedOutput();
            if (connectedOutput == null || !connectedOutput.isMine(this))
                return false;
        }

        for (final TransactionOutput output : tx.getOutputs()) {
            if (!output.isMine(this))
                return false;
        }

        return true;
    }

    public String getPaymentCode() {
        return getAccount(0).getStringPaymentCode();
    }

    public void resetBlockchainSync() {
        File chainFile = new File(directory, getCoinName()+".spvchain");
        if (chainFile.exists()) {
            log.debug("deleteSpvFile: exits");
            chainFile.delete();
        }
    }

    public String getMnemonicCode() {
        return Joiner.on(" ").join(getKeyChainSeed().getMnemonicCode());
    }

    public Address getCurrentAddress() {
        return currentReceiveAddress();
    }

    public Address getAddressFromBase58(String addr) {
        return Address.fromBase58(getNetworkParameters(), addr);
    }

    public boolean isValidAddress(String address) {
        try {
            Address.fromBase58(getNetworkParameters(), address);
            return true;
        } catch (AddressFormatException e) {
            try {
                CashAddress.decode(address);
                return true;
            } catch (AddressFormatException e2) {
                e2.printStackTrace();
                return false;
            }
        }
    }

    public Transaction createSend(String strAddr, long amount) throws InsufficientMoneyException {
        Address address;
        try {
            address = Address.fromBase58(getNetworkParameters(), strAddr);
        } catch (AddressFormatException e1) {
            try {
                address = CashAddress.decode(strAddr);
            } catch (AddressFormatException e2) {
                return null;
            }
        }
        return createSend(address, amount);
    }

    public Transaction createSend(Address address, long amount) throws InsufficientMoneyException {
        SendRequest sendRequest = SendRequest.to(address, Coin.valueOf(amount));
        if (!getNetworkParameters().getUseForkId()) {
            sendRequest.feePerKb = Coin.valueOf(141000);
        }
        completeTx(sendRequest);
        return sendRequest.tx;
    }

    public SendRequest makeNotificationTransaction(String paymentCode) throws InsufficientMoneyException {
        Bip47Account toBip47Account = new Bip47Account(getNetworkParameters(), paymentCode);
        Coin ntValue =  getNetworkParameters().getMinNonDustOutput();
        Address ntAddress = toBip47Account.getNotificationAddress();


        log.debug("Balance: " + getBalance());
        log.debug("To notification address: "+ntAddress.toString());
        log.debug("Value: "+ntValue.toFriendlyString());

        SendRequest sendRequest = SendRequest.to(ntAddress, ntValue);

        if (!getNetworkParameters().getUseForkId()) {
            sendRequest.feePerKb = Coin.valueOf(141000);
        }

        sendRequest.memo = "notification_transaction";

        FeeCalculation feeCalculation = WalletUtil.calculateFee(this, sendRequest, ntValue, calculateAllSpendCandidates());

        for (TransactionOutput output :feeCalculation.bestCoinSelection.gathered) {
            sendRequest.tx.addInput(output);
        }

        if (sendRequest.tx.getInputs().size() > 0) {
            TransactionInput txIn = sendRequest.tx.getInput(0);
            RedeemData redeemData = txIn.getConnectedRedeemData(this);
            checkNotNull(redeemData, "StashTransaction exists in wallet that we cannot redeem: %s", txIn.getOutpoint().getHash());
            log.debug("Keys: "+redeemData.keys.size());
            log.debug("Private key 0?: "+redeemData.keys.get(0).hasPrivKey());
            byte[] privKey = redeemData.getFullKey().getPrivKeyBytes();
            log.debug("Private key: "+ HEX.encode(privKey));
            byte[] pubKey = toBip47Account.getNotificationKey().getPubKey();
            log.debug("Public Key: "+ HEX.encode(pubKey));
            byte[] outpoint = txIn.getOutpoint().bitcoinSerialize();

            byte[] mask = null;
            try {
                SecretPoint secretPoint = new SecretPoint(privKey, pubKey);
                log.debug("Secret Point: "+ HEX.encode(secretPoint.ECDHSecretAsBytes()));
                log.debug("Outpoint: "+ HEX.encode(outpoint));
                mask = PaymentCode.getMask(secretPoint.ECDHSecretAsBytes(), outpoint);
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
                e.printStackTrace();
            }
            log.debug("My payment code: "+ mBip47Accounts.get(0).getPaymentCode().toString());
            log.debug("Mask: "+ HEX.encode(mask));
            byte[] op_return = PaymentCode.blind(mBip47Accounts.get(0).getPaymentCode().getPayload(), mask);

            sendRequest.tx.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(op_return));
        }

        completeTx(sendRequest);
        log.debug("Completed SendRequest");
        log.debug(sendRequest.toString());
        log.debug(sendRequest.tx.toString());

        sendRequest.tx.verify();

        return sendRequest;
    }

    public Transaction getSignedNotificationTransaction(SendRequest sendRequest, String paymentCode) {
        commitTx(sendRequest.tx);
        return sendRequest.tx;
    }

    public ListenableFuture<Transaction> broadcastTransaction(Transaction transactionToSend) {
        commitTx(transactionToSend);
        return vPeerGroup.broadcastTransaction(transactionToSend).future();
    }

    public boolean putBip47PaymentChannel(String profileId, String name) {
        if (channels.containsKey(profileId)) {
            Bip47PaymentChannel paymentChannel  = channels.get(profileId);
            if (!name.equals(paymentChannel.getLabel())) {
                paymentChannel.setLabel(name);
                return true;
            }
        } else {
            channels.put(profileId, new Bip47PaymentChannel(profileId, name));
            return true;
        }
        return false;
    }

    public void putPaymenCodeStatusSent(String paymentCode) {
        if (channels.containsKey(paymentCode)) {
            Bip47PaymentChannel paymentChannel  = channels.get(paymentCode);
            paymentChannel.setStatusSent();
        } else {
            putBip47PaymentChannel(paymentCode, paymentCode);
            putPaymenCodeStatusSent(paymentCode);
        }
    }

    public String getCurrentOutgoingAddress(Bip47PaymentChannel paymentChannel) {
        try {
            ECKey key = BIP47Util.getSendAddress(this, new PaymentCode(paymentChannel.getPaymentCode()), paymentChannel.getCurrentOutgoingIndex()).getSendECKey();
            return key.toAddress(getNetworkParameters()).toString();
        } catch (InvalidKeyException | InvalidKeySpecException | NotSecp256k1Exception | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    static class FeeCalculation {
        CoinSelection bestCoinSelection;
        TransactionOutput bestChangeOutput;
    }

    public void rescanTxBlock(Transaction tx) throws BlockStoreException {
       int blockHeight = tx.getConfidence().getAppearedAtChainHeight() - 2;
       this.vChain.rollbackBlockStore(blockHeight);
    }

    public BlockStore getBlockStore(){
        return vStore;
    }
}
