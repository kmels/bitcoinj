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
import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.*;
import org.bitcoinj.wallet.bip47.listeners.BlockchainDownloadProgressTracker;
import org.bitcoinj.wallet.bip47.listeners.TransactionEventListener;
import org.bitcoinj.crypto.bip47.Account;

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

/**
 * Created by jimmy on 9/28/17.
 */

/**
 * <p>A {@link Wallet} that runs in SPV mode and supports BIP 47 payments for coins BTC, BCH, tBTC and tBCH. You will
 * need to instantiate one wallet per supported coin.</p>
 *
 * <p>It produces two files in a designated directory. The directory name is the coin name. and is created in workingDirectory: </p>
 * <ul>
 *     <il>The .spvchain (blockstore): maintains a maximum # of headers mapped to memory (5000)</il>
 *     <il>The .wallet: stores the wallet with txs, can be encrypted, storing keys</il>
 * </ul>
 *
 * <p>By calling {@link Wallet.start()}, this wallet will automatically import payment addresses when a Bip 47
 * notification transaction is received.</p>
 *
 */

public class Wallet extends org.bitcoinj.wallet.Wallet {
    // the blokstore is used by a blockchain as a memory data structure
    private volatile BlockChain vChain;
    private volatile BlockStore vStore;
    // the blockchain is used by the peergroup
    private volatile PeerGroup vPeerGroup;
    // the directory will have the spvchain and the wallet files
    private volatile File directory;
    private volatile File walletFile;
    // the coin name that this wallet supports. Can be: BTC, tBTC, BCH, tBCH
    private String coin;

    // Wether this wallet is restored from a BIP39 seed and will need to replay the complete blockchain
    // Will be null if it's not a restored wallet.
    private DeterministicSeed restoreFromSeed;

    // Support for BIP47-type accounts. Only 1 account supported by this wallet initially
    private List<Account> mAccounts = new ArrayList<>(1);

    // The progress tracker will callback the listener with a porcetage of the blockchain that it has downloaded, while downloading..
    private BlockchainDownloadProgressTracker mBlockchainDownloadProgressTracker = null;
    // The transaction listener will
    //private TransactionEventListener mTransactionEventListener = null;

    private TransactionEventListener mCoinsReceivedEventListener = null;
    private TransactionEventListener mTransactionConfidenceListener = null;

    private boolean mBlockchainDownloadStarted = false;
    private ConcurrentHashMap<String, Bip47PaymentChannel> Bip47PaymentChannelData = new ConcurrentHashMap<>();
    private static final Logger log = LoggerFactory.getLogger(Wallet.class);

    public Wallet(NetworkParameters params, File workingDir, String coin, @Nullable DeterministicSeed deterministicSeed) throws Exception {
        super(params);
        Context.propagate(new Context(getNetworkParameters()));
        this.directory = new File(workingDir, coin);

        if (!this.directory.exists()) {
            if (!this.directory.mkdirs()) {
                throw new IOException("Could not create directory " + directory.getAbsolutePath());
            }
        }

        this.coin = coin;
        this.restoreFromSeed = deterministicSeed;

        File walletFile = new File(directory, coin + ".wallet");
        boolean chainFileExists = getChainFile().exists();
        boolean shouldReplayWallet = (walletFile.exists() && !chainFileExists) || deterministicSeed != null;

        Context.propagate(new Context(getNetworkParameters()));

        org.bitcoinj.wallet.Wallet coreWallet;

        // if the coin is existent, we should load it as a core Wallet and then we will manually set each of the Wallet's properties
        if (walletFile.exists()) {
            coreWallet = load(getNetworkParameters(), shouldReplayWallet, walletFile);
        } else {
            coreWallet = create(getNetworkParameters());
            coreWallet.freshReceiveKey();
            coreWallet.saveToFile(walletFile);
            coreWallet = load(getNetworkParameters(), false, walletFile);
        }

        checkNotNull(coreWallet);
        autosaveToFile(walletFile, 5, TimeUnit.SECONDS, null);

        // add to this wallet all the core Wallet's properties
        //  - watched scripts
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
            //  - last block state
            setLastBlockSeenHash(coreWallet.getLastBlockSeenHash());
            setLastBlockSeenHeight(coreWallet.getLastBlockSeenHeight());
            setLastBlockSeenTimeSecs(coreWallet.getLastBlockSeenTimeSecs());

            //  - transaction outputs to point to inputs that spend them
            Iterator<WalletTransaction> iter = coreWallet.getWalletTransactions().iterator();
            while(iter.hasNext())
                addWalletTransaction(iter.next());

            //  -  timestamp to use as a starting point to possibly invalidate keys created before this time
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

        //  - create the bip47 account
        createAccount(params);

        Address notificationAddress = mAccounts.get(0).getNotificationAddress();
        log.debug("Wallet notification address: "+notificationAddress.toString());

        if (!coreWallet.isAddressWatched(notificationAddress)) {
            addWatchedAddress(notificationAddress);
        }

        allowSpendingUnconfirmedTransactions();

        // init
        File chainFile = getChainFile();

        // Initiate Bitcoin network objects (block store, blockchain and peer group)
        vStore = new SPVBlockStore(getNetworkParameters(), chainFile);
        if (restoreFromSeed != null && chainFileExists) {
            log.info( "Deleting the chain file in preparation from restore.");
            vStore.close();
            if (!chainFile.delete())
                log.warn("start: ", new IOException("Failed to delete chain file in preparation for restore."));
            vStore = new SPVBlockStore(getNetworkParameters(), chainFile);
        }
        vChain = new BlockChain(getNetworkParameters(), vStore);
        vPeerGroup = new PeerGroup(getNetworkParameters(), vChain);

        // add Stash-Crypto nodes
        if (getCoin().equals("BCH")) {
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("158.69.119.35"), 8333));
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("144.217.73.86"), 8333));
        } else if (getCoin().equals("tBCH")) {
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("158.69.119.35"), 8333));
            vPeerGroup.addAddress(new PeerAddress(InetAddresses.forString("144.217.73.86"), 18333));
        }

        // connect to peer running in localhost
        vPeerGroup.setUseLocalhostPeerWhenPossible(true);
        // connect to peers in the coin network
        vPeerGroup.addPeerDiscovery(new DnsDiscovery(getNetworkParameters()));

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
            public void onTransactionReceived(Wallet wallet, Transaction transaction) {

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
            public void onTransactionConfidenceEvent(Wallet wallet, Transaction transaction) {
                return;
            }
        });
        log.debug("Created wallet: " +toString());
    }

    public Wallet(NetworkParameters params, KeyChainGroup kcg){
        super(params, kcg);
    }

    // Return the wallet's SPVChain
    protected File getChainFile(){
        return new File(directory, getCoin() + ".spvchain");
    }

    // Load an offline wallet from a file and return a @{link org.bitcoinj.wallet.Wallet}.
    // If shouldReplayWallet is false, the wallet last block is reset to -1
    private static org.bitcoinj.wallet.Wallet load(NetworkParameters networkParameters, boolean shouldReplayWallet, File vWalletFile) throws Exception {
        try (FileInputStream walletStream = new FileInputStream(vWalletFile)) {
            Protos.Wallet proto = WalletProtobufSerializer.parseToProto(walletStream);
            final WalletProtobufSerializer serializer = new WalletProtobufSerializer();
            org.bitcoinj.wallet.Wallet wallet = serializer.readWallet(networkParameters, null, proto);
            if (shouldReplayWallet)
                wallet.reset();
            return wallet;
        }
    }

    private Wallet create(NetworkParameters networkParameters) throws IOException {
        KeyChainGroup kcg;
        if (restoreFromSeed != null)
            kcg = new KeyChainGroup(networkParameters, restoreFromSeed);
        else
            kcg = new KeyChainGroup(networkParameters);
        return new Wallet(networkParameters, kcg);  // default
    }

    public String getCoin() {
        return this.coin;
    }

    protected void createAccount(NetworkParameters networkParameters) {
        log.debug("Seed: "+this.getKeyChainSeed());

        byte[] hd_seed = this.getKeyChainSeed().getSeedBytes();

        //
        byte[] hd_seed2 = restoreFromSeed.getSeedBytes();
        DeterministicKey mKey = HDKeyDerivation.createMasterPrivateKey(hd_seed2);
        DeterministicKey purposeKey = HDKeyDerivation.deriveChildKey(mKey, 47 | ChildNumber.HARDENED_BIT);
        DeterministicKey coinKey = HDKeyDerivation.deriveChildKey(purposeKey, ChildNumber.HARDENED_BIT);
        Account account = new Account(networkParameters, coinKey, 0);

        mAccounts.clear();
        mAccounts.add(account);
    }

    public void start(boolean startBlockchainDownload) {
        if (startBlockchainDownload) {
            startBlockchainDownload();
        }
    }

    private void startBlockchainDownload() {
        if (isStarted() && !mBlockchainDownloadStarted) {
            log.debug("Starting blockchain download.");
            vPeerGroup.start();
            vPeerGroup.startBlockChainDownload(mBlockchainDownloadProgressTracker);
            mBlockchainDownloadStarted = true;
        }
    }

    public List<Peer> getConnectedPeers() {
        return vPeerGroup.getConnectedPeers();
    }

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

        mBlockchainDownloadStarted = false;

        log.debug("stopWallet: Done");
    }

    public boolean isStarted() {
        return vStore != null;
    }

    public void setBlockchainDownloadProgressTracker(BlockchainDownloadProgressTracker downloadProgressTracker) {
        mBlockchainDownloadProgressTracker = downloadProgressTracker;
    }

    /**
     *
     */
    public boolean loadBip47PaymentChannelData() {
        String jsonString = readBip47PaymentChannelDataFile();

        if (StringUtils.isEmpty(jsonString)) {
            return false;
        }

        log.debug("loadBip47PaymentChannelData: "+jsonString);

        return importBip47PaymentChannelData(jsonString);
    }

    public String readBip47PaymentChannelDataFile() {
        File file = new File(directory, getCoin().concat(".bip47"));
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

    public boolean importBip47PaymentChannelData(String jsonString) {
        log.debug("loadBip47PaymentChannelData: "+jsonString);

        Gson gson = new Gson();
        Type collectionType = new TypeToken<Collection<Bip47PaymentChannel>>(){}.getType();
        try {
            List<Bip47PaymentChannel> Bip47PaymentChannelList = gson.fromJson(jsonString, collectionType);
            if (Bip47PaymentChannelList != null) {
                for (Bip47PaymentChannel paymentChannel: Bip47PaymentChannelList) {
                    Bip47PaymentChannelData.put(paymentChannel.getPaymentCode(), paymentChannel);
                }
            }
        } catch (JsonSyntaxException e) {
            return true;
        }
        return false;
    }

    public synchronized void saveBip47PaymentChannelData() {
        try {
            saveToFile(walletFile);
        } catch (IOException io){
            log.error("Failed to save wallet file",io);
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(Bip47PaymentChannelData.values());

        log.debug("saveBip47PaymentChannelData: "+json);

        File file = new File(directory, getCoin().concat(".bip47"));

        try {
            FileUtils.writeStringToFile(file, json, Charset.defaultCharset(), false);
            log.debug("saveBip47PaymentChannelData: saved");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void addOnReceiveTransactionListener(TransactionEventListener transactionEventListener){
        if (this.mCoinsReceivedEventListener != null)
            this.removeCoinsReceivedEventListener(mCoinsReceivedEventListener);

        transactionEventListener.setWallet(this);
        this.addCoinsReceivedEventListener(transactionEventListener);

        mCoinsReceivedEventListener = transactionEventListener;
    }

    public void addTransactionConfidenceEventListener(TransactionEventListener transactionEventListener){
        if (this.mTransactionConfidenceListener != null)
            this.removeTransactionConfidenceEventListener(mTransactionConfidenceListener);

        transactionEventListener.setWallet(this);
        this.addTransactionConfidenceEventListener(transactionEventListener);

        mTransactionConfidenceListener = transactionEventListener;
    }

    public boolean isNotificationTransaction(Transaction tx) {
        Address address = getAddressOfReceived(tx);
        Address myNotificationAddress = mAccounts.get(0).getNotificationAddress();

        return address != null && address.toString().equals(myNotificationAddress.toString());
    }

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
        byte[] privKeyBytes = mAccounts.get(0).getNotificationKey().getPrivKeyBytes();

        return BIP47Util.getPaymentCodeInNotificationTransaction(privKeyBytes, tx);
    }

    // <p> Receives a payment code and returns true iff there is already an incoming address generated for the channel</p>
    public boolean savePaymentCode(PaymentCode paymentCode) {
        if (Bip47PaymentChannelData.containsKey(paymentCode.toString())) {
            Bip47PaymentChannel paymentChannel = Bip47PaymentChannelData.get(paymentCode.toString());
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
            Bip47PaymentChannelData.put(paymentCode.toString(), paymentChannel);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public Account getAccount(int i) {
        return mAccounts.get(i);
    }

    public Address getAddressOfKey(ECKey key) {
        return key.toAddress(getNetworkParameters());
    }

    public boolean generateNewBip47IncomingAddress(String address) {
        for (Bip47PaymentChannel paymentChannel  : Bip47PaymentChannelData.values()) {
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
        for (Bip47PaymentChannel paymentChannel  : Bip47PaymentChannelData.values()) {
            for (Bip47Address bip47Address : paymentChannel.getIncomingAddresses()) {
                if (bip47Address.getAddress().equals(address)) {
                    return paymentChannel;
                }
            }
        }
        return null;
    }

    public String getPaymentCodeForAddress(String address) {
        for (Bip47PaymentChannel paymentChannel  : Bip47PaymentChannelData.values()) {
            for (Bip47Address bip47Address : paymentChannel.getIncomingAddresses()) {
                if (bip47Address.getAddress().equals(address)) {
                    return paymentChannel.getPaymentCode();
                }
            }
        }
        return null;
    }

    public Bip47PaymentChannel getBip47PaymentChannelForOutgoingAddress(String address) {
        for (Bip47PaymentChannel paymentChannel  : Bip47PaymentChannelData.values()) {
            for (String outgoingAddress : paymentChannel.getOutgoingAddresses()) {
                if (outgoingAddress.equals(address)) {
                    return paymentChannel;
                }
            }
        }
        return null;
    }

    public Bip47PaymentChannel getBip47PaymentChannelForPaymentCode(String paymentCode) {
        for (Bip47PaymentChannel paymentChannel  : Bip47PaymentChannelData.values()) {
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
        File chainFile = new File(directory, getCoin()+".spvchain");
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

    public SendRequest makeNotificationTransaction(String paymentCode, boolean complete) throws InsufficientMoneyException {
        Account toAccount = new Account(getNetworkParameters(), paymentCode);
        Coin ntValue =  getNetworkParameters().getMinNonDustOutput();
        Address ntAddress = toAccount.getNotificationAddress();


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
            log.debug("Private key: "+ Utils.HEX.encode(privKey));
            byte[] pubKey = toAccount.getNotificationKey().getPubKey();
            log.debug("Public Key: "+Utils.HEX.encode(pubKey));
            byte[] outpoint = txIn.getOutpoint().bitcoinSerialize();

            byte[] mask = null;
            try {
                SecretPoint secretPoint = new SecretPoint(privKey, pubKey);
                log.debug("Secret Point: "+Utils.HEX.encode(secretPoint.ECDHSecretAsBytes()));
                log.debug("Outpoint: "+Utils.HEX.encode(outpoint));
                mask = PaymentCode.getMask(secretPoint.ECDHSecretAsBytes(), outpoint);
            } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
                e.printStackTrace();
            }
            log.debug("My payment code: "+mAccounts.get(0).getPaymentCode().toString());
            log.debug("Mask: "+Utils.HEX.encode(mask));
            byte[] op_return = PaymentCode.blind(mAccounts.get(0).getPaymentCode().getPayload(), mask);

            sendRequest.tx.addOutput(Coin.ZERO, ScriptBuilder.createOpReturnScript(op_return));
        }

        if (complete)
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
        if (Bip47PaymentChannelData.containsKey(profileId)) {
            Bip47PaymentChannel paymentChannel  = Bip47PaymentChannelData.get(profileId);
            if (!name.equals(paymentChannel.getLabel())) {
                paymentChannel.setLabel(name);
                return true;
            }
        } else {
            Bip47PaymentChannelData.put(profileId, new Bip47PaymentChannel(profileId, name));
            return true;
        }
        return false;
    }

    public void putPaymenCodeStatusSent(String paymentCode) {
        if (Bip47PaymentChannelData.containsKey(paymentCode)) {
            Bip47PaymentChannel paymentChannel  = Bip47PaymentChannelData.get(paymentCode);
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

}
