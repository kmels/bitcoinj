package org.bitcoinj.wallet.bip47;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.params.BCCMainNetParams;
import org.bitcoinj.params.BCCTestNet3Params;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.testing.TestWithBip47Wallet;
import org.bitcoinj.wallet.*;
import org.bitcoinj.wallet.bip47.models.StashDeterministicSeed;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.Security;
import java.util.List;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;
import org.bitcoinj.crypto.MnemonicCodeTest;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class Bip47WalletTest extends TestWithBip47Wallet {
    private static final Logger log = LoggerFactory.getLogger(org.bitcoinj.wallet.WalletTest.class);

    //  - test vectors
    private final String ALICE_BIP39_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion";
    private final String ALICE_BIP39_RAW_ENTROPY = "b7b8706d714d9166e66e7ed5b3c61048";
    private final String ALICE_BIP32_SEED = "64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a";
    private final String ALICE_PAYMENT_CODE_V1 = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
    private final String ALICE_NOTIFICATION_ADDRESS = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";

    private final String BOB_BIP39_MNEMONIC = "reward upper indicate eight swift arch injury crystal super wrestle already dentist";
    private final String BOB_BIP39_RAW_ENTROPY = "b8bde1cba37dbc161d09aad9bfc81c9d";
    private final String BOB_BIP32_SEED = "87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110";
    private final String BOB_PAYMENT_CODE_V1 = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";
    private final String BOB_NOTIFICATION_ADDRESS = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV";

    private final String CHANNEL_NTX = "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000"
            + "006b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcf"
            + "c0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3"
            + "f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4"
            + "c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e252897931"
            + "1c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000";

    private final String CARLOS_BIP39_MNEMONIC = "fetch genuine seek want smile sea orient elbow basic where arrange display mask country walnut shuffle usage airport juice price grant scan wild alone";
    private final String CARLOS_PAYMENT_CODE = "PM8TJaWSfZYLLuJnXctJ8npNYrUr5UCeT6KGmayJ4ENDSqj7VZr7uyX9exCo5JA8mFLkeXPaHoCBKuMDpYFs3tdxP2UxNiHSsZtb1KkKSVQyiwFhdLTZ";


    private final Address OTHER_ADDRESS = new ECKey().toAddress(PARAMS);


    //  - blockchains to test
    public static final String[] SUPPORTED_COINS = { "BCH", "BTC", "tBCH", "tBTC" };

    // -

    static {
        // Adds a new provider, at a specified position
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 2);
        Security.addProvider(new BouncyCastleProvider());
    }
    private Wallet createWallet(Blockchain b, File workingDir, String mnemonic) throws Exception {
        StashDeterministicSeed seed = new StashDeterministicSeed(mnemonic, "", Utils.currentTimeSeconds());
        return new Wallet(b, workingDir, seed);
    };

    @Test
    public void aliceWalletTest() throws Exception {

        //  - test bip 39
        MnemonicCode mc = new MnemonicCode();
        List<String> code = mc.toMnemonic(HEX.decode(ALICE_BIP39_RAW_ENTROPY));
        byte[] seed = MnemonicCode.toSeed(code,"");
        byte[] entropy = mc.toEntropy(MnemonicCodeTest.split(ALICE_BIP39_MNEMONIC));

        assertEquals(ALICE_BIP39_RAW_ENTROPY, HEX.encode(entropy));
        assertEquals(ALICE_BIP39_MNEMONIC, Utils.join(code));
        assertEquals(ALICE_BIP32_SEED, HEX.encode(seed));

        File workingDir = new File("alice");

        Blockchain b = new Blockchain(0, MainNetParams.get(), SUPPORTED_COINS[1], "Bitcoin Core");
        //  - test bip 47
        Wallet w = createWallet(b,workingDir,ALICE_BIP39_MNEMONIC);
        assertEquals("xpub6D3t231wUi5v9PEa8mgmyV7Tovg3CzrGEUGNQTfm9cK93je3PgX9udfhzUDx29pkeeHQBPpTSHpAxnDgsf2XRbvLrmbCUQybjtHx8SUb3JB", w.getAccount(0).getXPub());
        byte[] BTC_PUBKEY = w.getAccount(0).getPaymentCode().getPubKey();
        //assertEquals("xpub6D3t231wUi5v9PEa8mgmyV7Tovg3CzrGEUGNQTfm9cK93je3PgX9udfhzUDx29pkeeHQBPpTSHpAxnDgsf2XRbvLrmbCUQybjtHx8SUb3JB", w.getAccount(0).getPaymentCode().getPubKey());
        assertEquals(ALICE_PAYMENT_CODE_V1, w.getPaymentCode());
        assertEquals(ALICE_NOTIFICATION_ADDRESS, w.getAccount(0).getNotificationAddress().toString());

        b = new Blockchain(1, TestNet3Params.get(), SUPPORTED_COINS[3], "Test Bitcoin Core");
        w = createWallet(b,workingDir,ALICE_BIP39_MNEMONIC);
        //assertEquals("tpubDEctaKJzZ8eirGRVS7QREGzP2aX8VnnaLxEZtiRM8HQUah42oBtWxvdsviTbExdfQHHaVj3RxroN12iFNbR89XhLQbRFuQrwFjT2ZfZ99aJ", w.getAccount(0).getXPub());
        //assertEquals("xpub6D3t231wUi5v9PEa8mgmyV7Tovg3CzrGEUGNQTfm9cK93je3PgX9udfhzUDx29pkeeHQBPpTSHpAxnDgsf2XRbvLrmbCUQybjtHx8SUb3JB", w.getAccount(0).getXPub());
        byte[] tBTC_PUBKEY = w.getAccount(0).getPaymentCode().getPubKey();
        assertEquals(HEX.encode(tBTC_PUBKEY), HEX.encode(BTC_PUBKEY));
        assertEquals(ALICE_PAYMENT_CODE_V1, w.getPaymentCode());
        //assertEquals(ALICE_NOTIFICATION_ADDRESS, w.getAccount(0).getNotificationAddress().toString());

        b = new Blockchain(2, BCCMainNetParams.get(), SUPPORTED_COINS[0], "Bitcoin Cash");
        w = createWallet(b,workingDir,ALICE_BIP39_MNEMONIC);
        assertEquals("xpub6D3t231wUi5v9PEa8mgmyV7Tovg3CzrGEUGNQTfm9cK93je3PgX9udfhzUDx29pkeeHQBPpTSHpAxnDgsf2XRbvLrmbCUQybjtHx8SUb3JB", w.getAccount(0).getXPub());
        byte[] BCH_PUBKEY = w.getAccount(0).getPaymentCode().getPubKey();
        assertEquals(HEX.encode(tBTC_PUBKEY), HEX.encode(BCH_PUBKEY));
        assertEquals(ALICE_PAYMENT_CODE_V1, w.getPaymentCode());
        assertEquals(ALICE_NOTIFICATION_ADDRESS, w.getAccount(0).getNotificationAddress().toString());

        b = new Blockchain(3, BCCTestNet3Params.get(), SUPPORTED_COINS[2], "Test Bitcoin Cash");
        w = createWallet(b,workingDir,ALICE_BIP39_MNEMONIC);
        byte[] tBCH_PUBKEY = w.getAccount(0).getPaymentCode().getPubKey();
        assertEquals(HEX.encode(tBCH_PUBKEY), HEX.encode(BCH_PUBKEY));
        //assertEquals(ALICE_BIP44_PUBKEY, w.getAccount(0).getXPub());
        assertEquals(ALICE_PAYMENT_CODE_V1, w.getPaymentCode());
        //assertEquals(ALICE_NOTIFICATION_ADDRESS, w.getAccount(0).getNotificationAddress().toString());

    }

    @Test
    public void bobWalletTest() throws Exception {
        //  - test bip 39
        MnemonicCode mc = new MnemonicCode();
        List<String> code = mc.toMnemonic(HEX.decode(BOB_BIP39_RAW_ENTROPY));
        byte[] seed = MnemonicCode.toSeed(code,"");
        byte[] entropy = mc.toEntropy(MnemonicCodeTest.split(BOB_BIP39_MNEMONIC));
        assertEquals(BOB_BIP39_RAW_ENTROPY, HEX.encode(entropy));
        assertEquals(BOB_BIP39_MNEMONIC, Utils.join(code));
        assertEquals(BOB_BIP32_SEED, HEX.encode(seed));

        File workingDir = new File("bob");

        Blockchain b = new Blockchain(0, MainNetParams.get(), SUPPORTED_COINS[1], "Bitcoin Core");
        Wallet w = createWallet(b,workingDir,BOB_BIP39_MNEMONIC);
        //assertEquals("tpubDCyvczNnKRM37QUHTCG1d6dFbXXkPUNfoay6XjVRhBKaGy47i1nFJQEmusyybMjaHBgpBbPFJRvwsWjtqQ8GTNiDw62ngm18w3QqyV6eHrY", w.getAccount(0).getXPub());
        assertEquals(BOB_PAYMENT_CODE_V1, w.getPaymentCode());

        b = new Blockchain(1, TestNet3Params.get(), SUPPORTED_COINS[3], "Test Bitcoin Core");
        w = createWallet(b,workingDir,BOB_BIP39_MNEMONIC);
        //assertEquals("tpubDDf84AmZb36BcJKZHrpuToRNj9bhDEwQ1PbrZ7guzq3EHFLxhW9ZjtghxLZauHVwXsm42wSRRxrNEkbFJu4qmvA1PyK8rYTa1o33XVsr6vw", w.getAccount(0).getXPub());
        assertEquals(BOB_PAYMENT_CODE_V1, w.getPaymentCode());
        //assertEquals(BOB_NOTIFICATION_ADDRESS, w.getAccount(0).getNotificationAddress().toString());

        b = new Blockchain(2, BCCMainNetParams.get(), SUPPORTED_COINS[0], "Bitcoin Cash");
        w = createWallet(b,workingDir,BOB_BIP39_MNEMONIC);
        //assertEquals(BOB_BIP44_PUBKEY, w.getAccount(0).getXPub());
        assertEquals(BOB_PAYMENT_CODE_V1, w.getPaymentCode());
        assertEquals(BOB_NOTIFICATION_ADDRESS, w.getAccount(0).getNotificationAddress().toString());

        b = new Blockchain(3, BCCTestNet3Params.get(), SUPPORTED_COINS[2], "Test Bitcoin Cash");
        w = createWallet(b,workingDir,BOB_BIP39_MNEMONIC);
        //assertEquals(BOB_BIP44_PUBKEY, w.getAccount(0).getXPub());
        assertEquals(BOB_PAYMENT_CODE_V1, w.getPaymentCode());
        //assertEquals(BOB_NOTIFICATION_ADDRESS, w.getAccount(0).getNotificationAddress().toString());
    }

    @Test
    public void notificationTransactionTest() throws Exception {
        super.setUp();
        // folders for alice and bob wallets
        File aliceDir = new File("alice2");
        File bobDir = new File("bob2");

        Blockchain b = new Blockchain(0, MainNetParams.get(), SUPPORTED_COINS[1], "Bitcoin Core");

        Wallet Alice = createWallet(b, aliceDir, ALICE_BIP39_MNEMONIC);
        Wallet Bob = createWallet(b, bobDir, BOB_BIP39_MNEMONIC);

        // Alice sends a payment to Bob, she saves Bob's payment code.

        setWallet(Alice);
        sendMoneyToWallet(Alice.getvWallet(), AbstractBlockChain.NewBlockType.BEST_CHAIN, Coin.COIN, Alice.getCurrentAddress());

        //boolean needsSaving = Alice.savePaymentCode(Bob.getAccount(0).getPaymentCode());
        //assertTrue(needsSaving);

        SendRequest ntxRequest = Alice.makeNotificationTransaction(Bob.getPaymentCode());

        assertEquals("9414f1681fb1255bd168a806254321a837008dd4480c02226063183deb100204", ntxRequest.tx.getHash());

        //assertEquals("tpubDCyvczNnKRM37QUHTCG1d6dFbXXkPUNfoay6XjVRhBKaGy47i1nFJQEmusyybMjaHBgpBbPFJRvwsWjtqQ8GTNiDw62ngm18w3QqyV6eHrY", w.getAccount(0).getXPub());

    }

    @Test
    public void carlosWalletTest() throws Exception {
        File workingDir = new File("carlos");

        Blockchain b = new Blockchain(1, TestNet3Params.get(), SUPPORTED_COINS[3], "Test Bitcoin Core");
        Wallet w = createWallet(b,workingDir,CARLOS_BIP39_MNEMONIC);
        assertEquals("tpubDCfC54qrR5PkDXCL2TkCJ46pYbFt7CX3UDF9e7qxsQw8Nm9HQy7eZ7tL3FrHhJhxAZU8dwmqpzhntLxax93914cq8vQUTsAxcKPBBoZDm28", w.getAccount(0).getXPub());
        assertEquals(CARLOS_PAYMENT_CODE, w.getPaymentCode());

        b = new Blockchain(0, MainNetParams.get(), SUPPORTED_COINS[1], "Bitcoin Core");
        w = createWallet(b,workingDir,CARLOS_BIP39_MNEMONIC);
        //assertEquals("tpubDDX2RK6EL7nuqjxFuZZTKsyMDx7PvPnbXmAtwuZaL9QorhjtussQTW5ReBF3G8G3wAY3RyusFkW2AuWz8YsiNXtkHZn2DmJRXA6m3rRwH8A", w.getAccount(0).getXPub());

    }
}
