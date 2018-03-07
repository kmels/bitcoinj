package org.bitcoinj.wallet.bip47;

import com.google.common.collect.Lists;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.testing.KeyChainTransactionSigner;
import org.bitcoinj.testing.TestWithWallet;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.MarriedKeyChain;
import org.bitcoinj.wallet.bip47.Wallet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.SecureRandom;
import java.util.List;

import static junit.framework.TestCase.assertTrue;
import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;
import org.bitcoinj.crypto.MnemonicCodeTest;
public class WalletTest extends TestWithWallet {
    private static final Logger log = LoggerFactory.getLogger(org.bitcoinj.wallet.WalletTest.class);

    //  - test vectors
    private final String ALICE_BIP39_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion";
    private final String ALICE_BIP39_RAW_ENTROPY = "b7b8706d714d9166e66e7ed5b3c61048";
    private final String ALICE_BIP32_SEED = "64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a";
    private final String ALICE_PAYMENT_CODE = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";

    private final Address OTHER_ADDRESS = new ECKey().toAddress(PARAMS);

    @Test
    public void aliceWalletTest() throws Exception {
        String coin = "BTC";
        NetworkParameters params = MainNetParams.get();
        File workingDir = new File(".");

        MnemonicCode mc = new MnemonicCode();
        List<String> code = mc.toMnemonic(HEX.decode(ALICE_BIP39_RAW_ENTROPY));
        byte[] seed = MnemonicCode.toSeed(code,"");
        byte[] entropy = mc.toEntropy(MnemonicCodeTest.split(ALICE_BIP39_MNEMONIC));

        assertEquals(ALICE_BIP39_RAW_ENTROPY, HEX.encode(entropy));
        assertEquals(ALICE_BIP39_MNEMONIC, Utils.join(code));
        assertEquals(ALICE_BIP32_SEED, HEX.encode(seed));

        DeterministicSeed dseed = new DeterministicSeed(ALICE_BIP39_MNEMONIC, null, "", Utils.currentTimeSeconds());
        Wallet w = new Wallet(params, workingDir, coin, dseed);

        String ALICE_BIP44_PUBKEY = "xpub6D3t231wUi5v9PEa8mgmyV7Tovg3CzrGEUGNQTfm9cK93je3PgX9udfhzUDx29pkeeHQBPpTSHpAxnDgsf2XRbvLrmbCUQybjtHx8SUb3JB";
        assertEquals(ALICE_BIP44_PUBKEY, w.getAccount(0).getXPub());
        assertEquals(ALICE_PAYMENT_CODE, w.getPaymentCode());

        //assertEquals(new PaymentCode())
    }
}
