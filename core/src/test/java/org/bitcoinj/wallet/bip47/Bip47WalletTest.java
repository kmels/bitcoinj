package org.bitcoinj.wallet.bip47;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.params.BCCMainNetParams;
import org.bitcoinj.params.BCCTestNet3Params;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.testing.TestWithWallet;
import org.bitcoinj.wallet.*;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.Security;
import java.util.List;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.bitcoinj.crypto.MnemonicCodeTest;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class Bip47WalletTest extends TestWithWallet {
    private static final Logger log = LoggerFactory.getLogger(org.bitcoinj.wallet.WalletTest.class);

    //  - test vectors
    private final String ALICE_BIP39_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion";
    private final String ALICE_BIP39_RAW_ENTROPY = "b7b8706d714d9166e66e7ed5b3c61048";
    private final String ALICE_BIP32_SEED = "64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a";
    private final String ALICE_PAYMENT_CODE_V1 = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
    private final String ALICE_NOTIFICATION_ADDRESS = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
    private final String ALICE_NOTIFICATION_TESTADDRESS = "mxjb4tLKWrRsG3sGSMfgRPcFvCPkVgM4td";

    private final String BOB_BIP39_MNEMONIC = "reward upper indicate eight swift arch injury crystal super wrestle already dentist";
    private final String BOB_BIP39_RAW_ENTROPY = "b8bde1cba37dbc161d09aad9bfc81c9d";
    private final String BOB_BIP32_SEED = "87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110";
    private final String BOB_PAYMENT_CODE_V1 = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";
    private final String BOB_NOTIFICATION_ADDRESS = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV";
    private final String BOB_NOTIFICATION_TESTADDRESS = "msDsmY1gh48jC28tu6DWCbZ2N83e9rqhR3";

    private final String SHARED_SECRET_0 = "f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef";
    private final String SHARED_SECRET_1 = "adfb9b18ee1c4460852806a8780802096d67a8c1766222598dc801076beb0b4d";
    private final String SHARED_SECRET_2 = "79e860c3eb885723bb5a1d54e5cecb7df5dc33b1d56802906762622fa3c18ee5";
    private final String SHARED_SECRET_3 = "d8339a01189872988ed4bd5954518485edebf52762bf698b75800ac38e32816d";
    private final String SHARED_SECRET_4  = "14c687bc1a01eb31e867e529fee73dd7540c51b9ff98f763adf1fc2f43f98e83";
    private final String SHARED_SECRET_5  = "725a8e3e4f74a50ee901af6444fb035cb8841e0f022da2201b65bc138c6066a2";
    private final String SHARED_SECRET_6  = "521bf140ed6fb5f1493a5164aafbd36d8a9e67696e7feb306611634f53aa9d1f";
    private final String SHARED_SECRET_7  = "5f5ecc738095a6fb1ea47acda4996f1206d3b30448f233ef6ed27baf77e81e46";
    private final String SHARED_SECRET_8  = "1e794128ac4c9837d7c3696bbc169a8ace40567dc262974206fcf581d56defb4";
    private final String SHARED_SECRET_9  = "fe36c27c62c99605d6cd7b63bf8d9fe85d753592b14744efca8be20a4d767c37";

    private final String CARLOS_BIP39_MNEMONIC = "fetch genuine seek want smile sea orient elbow basic where arrange display mask country walnut shuffle usage airport juice price grant scan wild alone";
    private final String CARLOS_PAYMENT_CODE = "PM8TJaWSfZYLLuJnXctJ8npNYrUr5UCeT6KGmayJ4ENDSqj7VZr7uyX9exCo5JA8mFLkeXPaHoCBKuMDpYFs3tdxP2UxNiHSsZtb1KkKSVQyiwFhdLTZ";

    private final String DAVE_BIP39_MNEMONIC = "clean album gap method clinic agree arm smooth walk divide mind raw dynamic stable tired truly address stumble small picnic volcano garage rural lawsuit";
    private final String DAVE_PAYMENT_CODE_V1 = "PM8TJVMmGDLDdKCm7x7cEQEsyTMtMVPCNdXrbMsTcE5C4GwRXmnNDXCYKn8GTWfZLgxkX6WNfhQUfUxQGrscJYaYGbR8k44PRvSuCRN1uKwWHeuCMsgD";
    private final String DAVE_BTC_NOTIFICATION_ADDRESS = "133mLY3JXcakBVPUSVFFBcnmDYRuvex9N4";
    private final String DAVE_TBTC_NOTIFICATION_ADDRESS = "mhZidb8HLe1zxbs6A4Dd1Y165Y2cvPtrpu";

    private Bip47Wallet bip47Bip47Wallet;

    //  - blockchains to test
    public static final String[] SUPPORTED_COINS = { "BCH", "BTC", "tBCH", "tBTC" };

    // -

    static {
        // Adds a new provider, at a specified position
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 2);
        Security.addProvider(new BouncyCastleProvider());
    }

    private Bip47Wallet createWallet(NetworkParameters params, File workingDir, String coin, String mnemonic) throws Exception {
        this.PARAMS = params;
        Context.propagate(new Context(PARAMS));
        DeterministicSeed seed = new DeterministicSeed(mnemonic, null, "", Utils.currentTimeSeconds());
        return new Bip47Wallet(params, workingDir, coin, seed);
    };

    static void deleteFolder(File dir){
        if (!dir.exists())
            return;
        String[] entries = dir.list();
        for(String s: entries){
            File currentFile = new File(dir.getPath(),s);
            if (currentFile.isDirectory())
                deleteFolder((currentFile));
            else
                currentFile.delete();
        }
        dir.delete();
    }


    public void testSeedFromMnemonic(String rawMnemonic, String rawSeed, String rawEntropy) throws Exception {
        // - test vectors with bip 39
        MnemonicCode mc = new MnemonicCode();
        List<String> code = mc.toMnemonic(HEX.decode(rawEntropy));
        byte[] seed = MnemonicCode.toSeed(code,"");
        byte[] entropy = mc.toEntropy(MnemonicCodeTest.split(rawMnemonic));

        assertEquals(rawEntropy, HEX.encode(entropy));
        assertEquals(rawMnemonic, Utils.join(code));
        assertEquals(rawSeed, HEX.encode(seed));
    }

    @Test
    public void aliceMnemonicTest() throws Exception {
        testSeedFromMnemonic(ALICE_BIP39_MNEMONIC, ALICE_BIP32_SEED, ALICE_BIP39_RAW_ENTROPY);
    }

    @Test
    public void bobMnemonicTest() throws Exception {
        testSeedFromMnemonic(BOB_BIP39_MNEMONIC, BOB_BIP32_SEED, BOB_BIP39_RAW_ENTROPY);
    }

    private void setUp(String dirName, NetworkParameters params, String coinName, String mnemonic) throws Exception {
        File workingDir = new File(dirName);
        Context.propagate(new Context(params));
        bip47Bip47Wallet = createWallet(params, workingDir, coinName, mnemonic);
        this.PARAMS = bip47Bip47Wallet.getNetworkParameters();
        super.setUp();
    }

    public void testAlicesWallet(NetworkParameters params, String coinName) throws Exception{
        this.setUp("alice", params, coinName, ALICE_BIP39_MNEMONIC);
        assertEquals(ALICE_PAYMENT_CODE_V1, bip47Bip47Wallet.getPaymentCode());
        if (params.getId().contains("production"))
            assertEquals(ALICE_NOTIFICATION_ADDRESS, bip47Bip47Wallet.getAccount(0).getNotificationAddress().toString());
        if (params.getId().contains("test"))
            assertEquals(ALICE_NOTIFICATION_TESTADDRESS, bip47Bip47Wallet.getAccount(0).getNotificationAddress().toString());
    }

    public void testBobsWallet(NetworkParameters params, String coinName) throws Exception{
        this.setUp("bob", params, coinName, BOB_BIP39_MNEMONIC);
        assertEquals(BOB_PAYMENT_CODE_V1, bip47Bip47Wallet.getPaymentCode());
        if (params.getId().contains("production"))
            assertEquals(BOB_NOTIFICATION_ADDRESS, bip47Bip47Wallet.getAccount(0).getNotificationAddress().toString());
        if (params.getId().contains("test"))
            assertEquals(BOB_NOTIFICATION_TESTADDRESS, bip47Bip47Wallet.getAccount(0).getNotificationAddress().toString());
    }

    public void testCarlosWallet(NetworkParameters params, String coinName) throws Exception{
        this.setUp("carlos", params, coinName, CARLOS_BIP39_MNEMONIC);
        assertEquals(CARLOS_PAYMENT_CODE, bip47Bip47Wallet.getPaymentCode());
    }

    public void testDavesWallet(NetworkParameters params, String coinName) throws Exception{
        this.setUp("dave", params, coinName, DAVE_BIP39_MNEMONIC);
        assertEquals(DAVE_PAYMENT_CODE_V1, bip47Bip47Wallet.getPaymentCode());
        if (params.getId().contains("production"))
            assertEquals(DAVE_BTC_NOTIFICATION_ADDRESS, bip47Bip47Wallet.getAccount(0).getNotificationAddress().toString());
        if (params.getId().contains("test"))
            assertEquals(DAVE_TBTC_NOTIFICATION_ADDRESS, bip47Bip47Wallet.getAccount(0).getNotificationAddress().toString());

    }

    @Test
    public void daveWallets() throws Exception{
        testDavesWallet(MainNetParams.get(), "BTC");
        testDavesWallet(BCCMainNetParams.get(), "BCH");
        assertTrue(Context.get().getParams().getId().contains("production"));
        testDavesWallet(TestNet3Params.get(), "tBTC");
        testDavesWallet(BCCTestNet3Params.get(), "tBCH");
        assertTrue(Context.get().getParams().getId().contains("test"));
    }

    @Test
    public void carlosWallets() throws Exception{
        testCarlosWallet(MainNetParams.get(), "BTC");
        testCarlosWallet(BCCMainNetParams.get(), "BCH");
        testCarlosWallet(TestNet3Params.get(), "tBTC");
        testCarlosWallet(BCCTestNet3Params.get(), "tBCH");
    }

    @Test
    public void aliceWallets() throws Exception{
        testAlicesWallet(MainNetParams.get(), "BTC");
        testAlicesWallet(BCCMainNetParams.get(), "BCH");
        testAlicesWallet(BCCTestNet3Params.get(), "tBCH");
        testAlicesWallet(TestNet3Params.get(), "tBTC");
    }

    @Test
    public void bobWallets() throws Exception{
        testBobsWallet(MainNetParams.get(), "BTC");
        testBobsWallet(TestNet3Params.get(), "tBTC");
        testBobsWallet(BCCMainNetParams.get(), "BCH");
        testBobsWallet(BCCTestNet3Params.get(), "tBCH");
    }

    @Test
    public void channelDerivationTests() throws Exception {
        // folders for alice and bob wallets
        File aliceDir = new File("alice2");
        File bobDir = new File("bob2");

        Bip47Wallet Alice = createWallet(MainNetParams.get(), aliceDir, "BTC", ALICE_BIP39_MNEMONIC);
        Bip47Wallet Bob = createWallet(MainNetParams.get(), bobDir, "BTC", BOB_BIP39_MNEMONIC);

        // Bob receives a NTX with Alice's payment code. Bob's wallet generates keys for Alice to use.
        Bob.savePaymentCode(Alice.getAccount(0).getPaymentCode()); // bob saves alice
        Bip47PaymentChannel channel = Bob.getBip47PaymentChannelForPaymentCode(Alice.getPaymentCode());
        assertEquals(10, channel.getIncomingAddresses().size()); // bob's # of incoming addresses

        //  - addresses used by Alice for sending to Bob
        assertEquals("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", channel.getIncomingAddresses().get(0).getAddress());
        assertEquals("12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6", channel.getIncomingAddresses().get(1).getAddress());
        assertEquals("1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc", channel.getIncomingAddresses().get(2).getAddress());
        assertEquals("1CZAmrbKL6fJ7wUxb99aETwXhcGeG3CpeA", channel.getIncomingAddresses().get(3).getAddress());
        assertEquals("1KQvRShk6NqPfpr4Ehd53XUhpemBXtJPTL", channel.getIncomingAddresses().get(4).getAddress());
        assertEquals("1KsLV2F47JAe6f8RtwzfqhjVa8mZEnTM7t", channel.getIncomingAddresses().get(5).getAddress());
        assertEquals("1DdK9TknVwvBrJe7urqFmaxEtGF2TMWxzD", channel.getIncomingAddresses().get(6).getAddress());
        assertEquals("16DpovNuhQJH7JUSZQFLBQgQYS4QB9Wy8e", channel.getIncomingAddresses().get(7).getAddress());
        assertEquals("17qK2RPGZMDcci2BLQ6Ry2PDGJErrNojT5", channel.getIncomingAddresses().get(8).getAddress());
        assertEquals("1GxfdfP286uE24qLZ9YRP3EWk2urqXgC4s", channel.getIncomingAddresses().get(9).getAddress());

        assertEquals(SHARED_SECRET_0, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 0).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_1, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 1).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_2, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 2).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_3, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 3).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_4, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 4).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_5, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 5).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_6, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 6).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_7, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 7).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_8, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 8).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_9, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 9).getSharedSecret().ECDHSecretAsBytes()));
    }

    @Test
    public void createAndLoadWallet() throws Exception{
        // create a fresh new wallet for Chuck
        File dir = new File("src/test/resources/org/bitcoinj/wallet/chuck-bip47");
        deleteFolder(dir);
        assertFalse(dir.exists()); //delete previous wallets created by this test
        Bip47Wallet ChuckBTC = new Bip47Wallet(MainNetParams.get(), dir, "BTC", null);
        assertTrue(dir.exists());

        // new files should have been created
        File btc = new File(dir,"BTC");
        File walletFile = new File(btc,"BTC.wallet");
        assertTrue(btc.exists());
        assertTrue(walletFile.exists());
        File spvFile = new File(btc,"BTC.spvchain");

        // Save the wallet's seed
        String chuckFreshPaymentCode = ChuckBTC.getPaymentCode();
        String chuckFreshMnemonic = ChuckBTC.getMnemonicCode();
        String chuckFreshSeedBytes = HEX.encode(ChuckBTC.getKeyChainSeed().getSeedBytes());

        // Load the core wallet, check if the seed is the same as when created
        org.bitcoinj.wallet.Wallet ChuckLoadedCore = Bip47Wallet.load(MainNetParams.get(), false, walletFile );
        assertEquals(HEX.encode(ChuckLoadedCore.getKeyChainSeed().getSeedBytes()), chuckFreshSeedBytes);

        // Close the store file, so that we can recreate a wallet from chuck without getting a file lock exception
        ChuckBTC.stop();
        assertTrue(walletFile.exists());

        ChuckBTC.getBlockStore().close();
        // Check that a creating a new Bip47 Wallet in the same directory/coin will have the same seed.
        Bip47Wallet ChuckLoadedBip47 = new Bip47Wallet(MainNetParams.get(), dir, "BTC", null);
        assertEquals(ChuckLoadedBip47.getMnemonicCode(), chuckFreshMnemonic);
        assertEquals(ChuckLoadedBip47.getPaymentCode(), chuckFreshPaymentCode);
        assertEquals(HEX.encode(ChuckLoadedCore.getKeyChainSeed().getSeedBytes()), chuckFreshSeedBytes);
    }

    /*
    @Test
    public void createAndLoadWallet() throws Exception{
        File dir = new File("src/test/resources/org/bitcoinj/wallet/chuck-bip47");
        deleteFolder(dir);
        assertFalse(dir.exists());

        Bip47Wallet ChuckBTC = new Bip47Wallet(MainNetParams.get(), dir, "BTC", null);
        assertTrue(dir.exists());

        File btc = new File(dir,"BTC");
        assertTrue(btc.exists());

        File walletFile = new File(btc,"BTC.wallet");
        assertTrue(walletFile.exists());

        String chuckFreshPaymentCode = ChuckBTC.getPaymentCode();
        String chuckFreshSeedBytes = HEX.encode(ChuckBTC.getKeyChainSeed().getSeedBytes());

        Wallet ChuckBTC2 = Bip47Wallet.load(MainNetParams.get(), false, walletFile );
        assertEquals(HEX.encode(ChuckBTC2.getKeyChainSeed().getSeedBytes()), chuckFreshSeedBytes);

        File spvFile = new File(btc,"BTC.spvchain");
        ChuckBTC.getBlockStore().close();
        //assertTrue(spvFile.delete());
        assertEquals(HEX.encode(ChuckBTC2.getKeyChainSeed().getSeedBytes()), chuckFreshSeedBytes);
        Bip47Wallet ChuckBTC3 =  new Bip47Wallet(MainNetParams.get(), dir, "BTC", null);

        //assertEquals(ChuckBTC2.getMnemonicCode(), ALICE_BIP39_MNEMONIC);
        assertEquals(ChuckBTC3.getPaymentCode(), chuckFreshPaymentCode);
    }
*/
    @Test
    public void loadAliceV1Wallet() throws Exception{
        File dir = new File("src/test/resources/org/bitcoinj/wallet/alice-bip47");
        assertTrue(dir.exists());

        File btc = new File(dir,"BTC");
        assertTrue(btc.exists());

        File walletFile = new File(btc,"BTC.wallet");
        assertTrue(walletFile.exists());

        Bip47Wallet AliceBTC = new Bip47Wallet(MainNetParams.get(), dir, "BTC", null);
        assertEquals(AliceBTC.getMnemonicCode(), ALICE_BIP39_MNEMONIC);
        assertEquals(AliceBTC.getAccount(0).getPaymentCode(), ALICE_PAYMENT_CODE_V1);
    }
}
