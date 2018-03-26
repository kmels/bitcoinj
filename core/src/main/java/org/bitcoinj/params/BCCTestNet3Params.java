/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.params;

import java.math.BigInteger;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import org.bitcoinj.core.*;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class BCCTestNet3Params extends AbstractBitcoinNetParams {

    private static final Logger log = LoggerFactory.getLogger(BCCTestNet3Params.class);

    /**
     * Scheme part for Bitcoin Cash TestNet URIs.
     */
    public static final String BITCOIN_CASH_TESTNET_SCHEME = "bchtest";

    // Aug, 1 hard fork
     int uahfHeight = 478559;
     /** Activation time at which the cash HF kicks in. */
     long cashHardForkActivationTime;

    int daaHeight;

    public BCCTestNet3Params() {
        super();
        id = ID_TESTNET;
        // Genesis hash is 000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
        packetMagic = 0xf4e5f3f4L;
        interval = INTERVAL;
        targetTimespan = TARGET_TIMESPAN;
        maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        port = 18333;
        addressHeader = 111;
        p2shHeader = 196;
        acceptableAddressCodes = new int[] { addressHeader, p2shHeader };
        dumpedPrivateKeyHeader = 239;
        genesisBlock.setTime(1296688602L);
        genesisBlock.setDifficultyTarget(0x1d00ffffL);
        genesisBlock.setNonce(414098458);
        spendableCoinbaseDepth = 100;
        subsidyDecreaseBlockCount = 210000;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        alertSigningKey = Utils.HEX.decode("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");

        dnsSeeds = new String[] {
                "testnet-seed.bitcoinabc.org",
                "testnet-seed-abc.bitcoinforks.org",
                "testnet-seed.bitcoinunlimited.info",
                "testnet-seed.bitprim.org",
                "testnet-seed.deadalnix.me",
                "testnet-seeder.criptolayer.net"
        };
        addrSeeds = null;
        bip32HeaderPub = 0x043587CF;
        bip32HeaderPriv = 0x04358394;

        majorityEnforceBlockUpgrade = TestNet2Params.TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TestNet2Params.TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TestNet2Params.TESTNET_MAJORITY_WINDOW;

        // Aug, 1 hard fork
        uahfHeight = 1155876;

        /** Activation time at which the cash HF kicks in. */
        cashHardForkActivationTime = 1510600000;

        daaHeight = 1188697;
    }

    private static BCCTestNet3Params instance;
    public static synchronized BCCTestNet3Params get() {
        if (instance == null) {
            instance = new BCCTestNet3Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_TESTNET;
    }

    @Override
    public int getMaxBlockSize() {
        return Block.BCC_MAX_BLOCK_SIZE;
    }

    @Override
    public int getMaxBlockSigops() {
        return Block.BCC_MAX_BLOCK_SIGOPS;
    }

    @Override
    public Coin getReferenceDefaultMinTxFee() {
        return Transaction.BCC_REFERENCE_DEFAULT_MIN_TX_FEE;
    }

    @Override
    public Coin getDefaultTxFee() {
        return Transaction.BCC_DEFAULT_TX_FEE;
    }

    @Override
    public Coin getMinNonDustOutput() {
        return Transaction.BCC_MIN_NONDUST_OUTPUT;
    }

    @Override
    public int getProtocolVersionNum(final ProtocolVersion version) {
        return version == ProtocolVersion.CURRENT? ProtocolVersion.BCC_CURRENT.getBitcoinProtocolVersion() : version.getBitcoinProtocolVersion();
    }

    @Override
    public boolean getUseForkId() {
        return true;
    }

    @Override
    public String getUriScheme() {
        return BITCOIN_CASH_TESTNET_SCHEME;
    }

    // February 16th 2012
    private static final Date testnetDiffDate = new Date(1329264000000L);

    @Override
    public void checkDifficultyTransitions(final StoredBlock storedPrev, final Block nextBlock,
                                           final BlockStore blockStore) throws VerificationException, BlockStoreException {
        if (storedPrev.getHeight() < daaHeight && !isDifficultyTransitionPoint(storedPrev) && nextBlock.getTime().after(testnetDiffDate)) {
            Block prev = storedPrev.getHeader();

            // After 15th February 2012 the rules on the testnet change to avoid people running up the difficulty
            // and then leaving, making it too hard to mine a block. On non-difficulty transition points, easy
            // blocks are allowed if there has been a span of 20 minutes without one.
            final long timeDelta = nextBlock.getTimeSeconds() - prev.getTimeSeconds();
            // There is an integer underflow bug in bitcoin-qt that means mindiff blocks are accepted when time
            // goes backwards.
            if (timeDelta >= 0 && timeDelta <= NetworkParameters.TARGET_SPACING * 2) {
                // Walk backwards until we find a block that doesn't have the easiest proof of work, then check
                // that difficulty is equal to that one.
                StoredBlock cursor = storedPrev;
                while (!cursor.getHeader().equals(getGenesisBlock()) &&
                        cursor.getHeight() % getInterval() != 0 &&
                        cursor.getHeader().getDifficultyTargetAsInteger().equals(getMaxTarget()))
                    cursor = cursor.getPrev(blockStore);
                BigInteger cursorTarget = cursor.getHeader().getDifficultyTargetAsInteger();
                BigInteger newTarget = nextBlock.getDifficultyTargetAsInteger();
                if (!cursorTarget.equals(newTarget))
                    throw new VerificationException("Testnet block transition that is not allowed: " +
                            Long.toHexString(cursor.getHeader().getDifficultyTarget()) + " vs " +
                            Long.toHexString(nextBlock.getDifficultyTarget()));
            }
        } else {

            Block prev = storedPrev.getHeader();

            if (storedPrev.getHeight() +1 >= daaHeight) {
                checkNextCashWorkRequired(storedPrev, nextBlock, blockStore);
                return;
            }

            // Is this supposed to be a difficulty transition point
            if (!isDifficultyTransitionPoint(storedPrev)) {

                if (storedPrev.getHeader().getDifficultyTargetAsInteger().equals(getMaxTarget())) {
                    // No ... so check the difficulty didn't actually change.
                    if (nextBlock.getDifficultyTarget() != prev.getDifficultyTarget())
                        throw new VerificationException("Unexpected change in difficulty at height " + storedPrev.getHeight() +
                                ": " + Long.toHexString(nextBlock.getDifficultyTarget()) + " vs " +
                                Long.toHexString(prev.getDifficultyTarget()));
                    return;
                }
                // If producing the last 6 block took less than 12h, we keep the same
                // difficulty.
                StoredBlock cursor = blockStore.get(prev.getHash());
                for (int i = 0; i < 6; i++) {
                    if (cursor == null) {
                        return;
                        // This should never happen. If it does, it means we are following an incorrect or busted chain.
                        //throw new VerificationException(
                        //      "We did not find a way back to the genesis block.");
                    }
                    cursor = blockStore.get(cursor.getHeader().getPrevBlockHash());
                }
                long mpt6blocks = 0;
                try {
                    //Check to see if there are enough blocks before cursor to correctly calculate the median time
                    StoredBlock beforeCursor = cursor;
                    for (int i = 0; i < 10; i++) {
                        beforeCursor = blockStore.get(beforeCursor.getHeader().getPrevBlockHash());
                        if (beforeCursor == null)
                            return; //Not enough blocks to check difficulty.
                    }
                    mpt6blocks = AbstractBlockChain.getMedianTimestampOfRecentBlocks(storedPrev, blockStore) - AbstractBlockChain.getMedianTimestampOfRecentBlocks(cursor, blockStore);
                } catch (NullPointerException x) {
                    return;
                }

                // If producing the last 6 block took more than 12h, increase the difficulty
                // target by 1/4 (which reduces the difficulty by 20%). This ensure the
                // chain do not get stuck in case we lose hashrate abruptly.
                if (mpt6blocks >= 12 * 3600) {
                    BigInteger nPow = storedPrev.getHeader().getDifficultyTargetAsInteger();
                    nPow = nPow.add(nPow.shiftRight(2));

                    if (nPow.compareTo(getMaxTarget()) > 0)
                        nPow = getMaxTarget();

                    if (nextBlock.getDifficultyTarget() != Utils.encodeCompactBits(nPow))
                        throw new VerificationException("Unexpected change in difficulty [6 blocks >12 hours] at height " + storedPrev.getHeight() +
                                ": " + Long.toHexString(nextBlock.getDifficultyTarget()) + " vs " +
                                Utils.encodeCompactBits(nPow));
                    return;
                }


                // No ... so check the difficulty didn't actually change.
                if (nextBlock.getDifficultyTarget() != prev.getDifficultyTarget())
                    throw new VerificationException("Unexpected change in difficulty at height " + storedPrev.getHeight() +
                            ": " + Long.toHexString(nextBlock.getDifficultyTarget()) + " vs " +
                            Long.toHexString(prev.getDifficultyTarget()));
                return;
            }

            // We need to find a block far back in the chain. It's OK that this is expensive because it only occurs every
            // two weeks after the initial block chain download.
            final Stopwatch watch = Stopwatch.createStarted();
            StoredBlock cursor = blockStore.get(prev.getHash());
            for (int i = 0; i < this.getInterval() - 1; i++) {
                if (cursor == null) {
                    // This should never happen. If it does, it means we are following an incorrect or busted chain.
                    throw new VerificationException(
                            "Difficulty transition point but we did not find a way back to the genesis block.");
                }
                cursor = blockStore.get(cursor.getHeader().getPrevBlockHash());
            }
            watch.stop();
            if (watch.elapsed(TimeUnit.MILLISECONDS) > 50)
                log.info("Difficulty transition traversal took {}", watch);

            Block blockIntervalAgo = cursor.getHeader();
            int timespan = (int) (prev.getTimeSeconds() - blockIntervalAgo.getTimeSeconds());
            // Limit the adjustment step.
            final int targetTimespan = this.getTargetTimespan();
            if (timespan < targetTimespan / 4)
                timespan = targetTimespan / 4;
            if (timespan > targetTimespan * 4)
                timespan = targetTimespan * 4;

            BigInteger newTarget = Utils.decodeCompactBits(prev.getDifficultyTarget());
            newTarget = newTarget.multiply(BigInteger.valueOf(timespan));
            newTarget = newTarget.divide(BigInteger.valueOf(targetTimespan));

            verifyDifficulty(newTarget, nextBlock);

            /*if (newTarget.compareTo(this.getMaxTarget()) > 0) {
                log.info("Difficulty hit proof of work limit: {}", newTarget.toString(16));
                newTarget = this.getMaxTarget();
            }
            int accuracyBytes = (int) (nextBlock.getDifficultyTarget() >>> 24) - 3;
            long receivedTargetCompact = nextBlock.getDifficultyTarget();
            // The calculated difficulty is to a higher precision than received, so reduce here.
            BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
            newTarget = newTarget.and(mask);
            long newTargetCompact = Utils.encodeCompactBits(newTarget);
            if (newTargetCompact != receivedTargetCompact)
                throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                        Long.toHexString(newTargetCompact) + " vs " + Long.toHexString(receivedTargetCompact));
                        */
        }
    }

    void verifyDifficulty(BigInteger newTarget, Block nextBlock) {
        if (newTarget.compareTo(this.getMaxTarget()) > 0) {
            log.info("Difficulty hit proof of work limit: {}", newTarget.toString(16));
            newTarget = this.getMaxTarget();
        }

        int accuracyBytes = (int) (nextBlock.getDifficultyTarget() >>> 24) - 3;
        long receivedTargetCompact = nextBlock.getDifficultyTarget();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newTarget = newTarget.and(mask);
        long newTargetCompact = Utils.encodeCompactBits(newTarget);

        if (newTargetCompact != receivedTargetCompact)
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    Long.toHexString(newTargetCompact) + " vs " + Long.toHexString(receivedTargetCompact));
    }

    /**
     * The number that is one greater than the largest representable SHA-256
     * hash.
     */
    private static BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);

    /**
     * Compute the a target based on the work done between 2 blocks and the time
     * required to produce that work.
     */
    BigInteger ComputeTarget(StoredBlock pindexFirst,
                             StoredBlock pindexLast) {

        Preconditions.checkState(pindexLast.getHeight() > pindexFirst.getHeight());

        /**
         * From the total work done and the time it took to produce that much work,
         * we can deduce how much work we expect to be produced in the targeted time
         * between blocks.
         */
        BigInteger work = pindexLast.getChainWork().subtract(pindexFirst.getChainWork());
        work = work.multiply(BigInteger.valueOf(this.TARGET_SPACING));

        // In order to avoid difficulty cliffs, we bound the amplitude of the
        // adjustement we are going to do.
        //assert(pindexLast->nTime > pindexFirst->nTime);
        long nActualTimespan = pindexLast.getHeader().getTimeSeconds() - pindexFirst.getHeader().getTimeSeconds();
        if (nActualTimespan > 288 * TARGET_SPACING) {
            nActualTimespan = 288 * TARGET_SPACING;
        } else if (nActualTimespan < 72 * TARGET_SPACING) {
            nActualTimespan = 72 * TARGET_SPACING;
        }

        work = work.divide(BigInteger.valueOf(nActualTimespan));

        /**
         * We need to compute T = (2^256 / W) - 1 but 2^256 doesn't fit in 256 bits.
         * By expressing 1 as W / W, we get (2^256 - W) / W, and we can compute
         * 2^256 - W as the complement of W.
         */
        //return (-work) / work;
        //return BigInteger.valueOf(2).pow(256).divide(work).subtract(BigInteger.valueOf(1));

        //return Block.LARGEST_HASH.divide(target.add(BigInteger.ONE))

        return LARGEST_HASH.divide(work).subtract(BigInteger.ONE);//target.add(BigInteger.ONE))
    }

    /**
     * To reduce the impact of timestamp manipulation, we select the block we are
     * basing our computation on via a median of 3.
     */
    StoredBlock GetSuitableBlock(StoredBlock pindex, BlockStore blockStore) throws BlockStoreException{
        //assert(pindex->nHeight >= 3);

        /**
         * In order to avoid a block is a very skewed timestamp to have too much
         * influence, we select the median of the 3 top most blocks as a starting
         * point.
         */
        StoredBlock blocks[] = new StoredBlock[3];
        blocks[2] = pindex;
        blocks[1] = pindex.getPrev(blockStore);
        blocks[0] = blocks[1].getPrev(blockStore);

        // Sorting network.
        if (blocks[0].getHeader().getTimeSeconds() > blocks[2].getHeader().getTimeSeconds()) {
            //std::swap(blocks[0], blocks[2]);
            StoredBlock temp = blocks[0];
            blocks[0] = blocks[2];
            blocks[2] = temp;
        }

        if (blocks[0].getHeader().getTimeSeconds() > blocks[1].getHeader().getTimeSeconds()) {
            //std::swap(blocks[0], blocks[1]);
            StoredBlock temp = blocks[0];
            blocks[0] = blocks[1];
            blocks[1] = temp;
        }

        if (blocks[1].getHeader().getTimeSeconds() > blocks[2].getHeader().getTimeSeconds()) {
            //std::swap(blocks[1], blocks[2]);
            StoredBlock temp = blocks[1];
            blocks[1] = blocks[2];
            blocks[2] = temp;
        }

        // We should have our candidate in the middle now.
        return blocks[1];
    }

    /**
     * Compute the next required proof of work using a weighted average of the
     * estimated hashrate per block.
     *
     * Using a weighted average ensure that the timestamp parameter cancels out in
     * most of the calculation - except for the timestamp of the first and last
     * block. Because timestamps are the least trustworthy information we have as
     * input, this ensures the algorithm is more resistant to malicious inputs.
     */
    void checkNextCashWorkRequired(StoredBlock storedPrev,
                                   Block nextBlock, BlockStore blockStore) {
        // This cannot handle the genesis block and early blocks in general.
        //assert(pindexPrev);



        // Compute the difficulty based on the full adjustement interval.
        int nHeight = storedPrev.getHeight();
        Preconditions.checkState(nHeight >= this.interval);

        // Get the last suitable block of the difficulty interval.
        try {

            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes then allow
            // mining of a min-difficulty block.

            Block prev = storedPrev.getHeader();


            final long timeDelta = nextBlock.getTimeSeconds() - prev.getTimeSeconds();
            if (timeDelta >= 0 && timeDelta > NetworkParameters.TARGET_SPACING * 2) {
                if (!maxTarget.equals(nextBlock.getDifficultyTargetAsInteger()))
                    throw new VerificationException("Testnet block transition that is not allowed: " +
                            Long.toHexString(Utils.encodeCompactBits(maxTarget)) + " (required min difficulty) vs " +
                            Long.toHexString(nextBlock.getDifficultyTarget()));
                return;
            }

            StoredBlock pindexLast = GetSuitableBlock(storedPrev, blockStore);
            //assert (pindexLast);

            // Get the first suitable block of the difficulty interval.
            int nHeightFirst = nHeight - 144;

            StoredBlock pindexFirst = storedPrev;

            for (int i = 144; i > 0; --i)
            {
                pindexFirst = pindexFirst.getPrev(blockStore);
                if(pindexFirst == null)
                    return;
            }

            pindexFirst = GetSuitableBlock(pindexFirst, blockStore);
            //assert (pindexFirst);

            // Compute the target based on time and work done during the interval.
            BigInteger nextTarget =
                    ComputeTarget(pindexFirst, pindexLast);

            verifyDifficulty(nextTarget, nextBlock);
        }
        catch (BlockStoreException x)
        {
            //this means we don't have enough blocks, yet.  let it go until we do.
            return;
        }
    }
}
