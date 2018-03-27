package org.bitcoinj.crypto.bip47;

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.params.BCCTestNet3Params;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.wallet.bip47.Bip47WalletTest;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

public class Bip47AccountTest  {
    private static final Logger log = LoggerFactory.getLogger(Bip47AccountTest.class);

    private final String ALICE_PAYMENT_CODE_V1 = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
    private final String ALICE_NOTIFICATION_ADDRESS = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
    private final String ALICE_NOTIFICATION_TESTADDRESS = "mxjb4tLKWrRsG3sGSMfgRPcFvCPkVgM4td";

    @Test
    public void constructFromPaymentCode() throws Exception {
        // a valid payment code
        Account acc = new Account(MainNetParams.get(), ALICE_PAYMENT_CODE_V1);
        assertEquals(acc.getStringPaymentCode(), ALICE_PAYMENT_CODE_V1);
        assertEquals(ALICE_NOTIFICATION_ADDRESS, acc.getNotificationAddress().toString());


        Account testAcc = new Account(BCCTestNet3Params.get(), ALICE_PAYMENT_CODE_V1);
        assertEquals(testAcc.getStringPaymentCode(), ALICE_PAYMENT_CODE_V1);
        assertEquals(ALICE_NOTIFICATION_TESTADDRESS, testAcc.getNotificationAddress().toString());

        // invalid payment code
        try {
            Account badAcc = new Account(MainNetParams.get(), ALICE_PAYMENT_CODE_V1.substring(0, 10));
        } catch (AddressFormatException expected){
            assertTrue(expected.getMessage().equalsIgnoreCase("Checksum does not validate"));
        }
    }
}