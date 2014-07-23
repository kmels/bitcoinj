/*
 * Copyright 2014 the bitcoinj authors
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
package com.google.bitcoin.core;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

/** Message representing a list of unspent transaction outputs, returned in response to sending a GetUTXOSMessage. */
public class UTXOSMessage extends Message {
    private long height;
    private Sha256Hash chainHead;
    private BitSet hitMap;

    private List<TransactionOutput> outputs;
    private long[] heights;

    /** This is a special sentinel value that can appear in the heights field if the given tx is in the mempool. */
    public static long MEMPOOL_HEIGHT = 0x7FFFFFFFL;

    public UTXOSMessage(NetworkParameters params, byte[] payloadBytes) {
        super(params, payloadBytes, 0);
    }

    /**
     * Provide an array of output objects, with nulls indicating that the output was missing. The bitset will
     * be calculated from this.
     */
    public UTXOSMessage(NetworkParameters params, List<TransactionOutput> outputs, long[] heights, Sha256Hash chainHead, long height) {
        super(params);
        hitMap = new BitSet(outputs.size());
        for (int i = 0; i < outputs.size(); i++) {
            hitMap.set(i, outputs.get(i) != null);
        }
        this.outputs = new ArrayList<TransactionOutput>(outputs.size());
        for (TransactionOutput output : outputs) {
            if (output != null) this.outputs.add(output);
        }
        this.chainHead = chainHead;
        this.height = height;
        this.heights = Arrays.copyOf(heights, heights.length);
    }

    @Override
    void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        Utils.uint32ToByteStreamLE(height, stream);
        stream.write(chainHead.getBytes());
        final byte[] bits = hitMap.toByteArray();
        if (bits.length == 0) {
            // One empty byte.
            stream.write(new VarInt(1).encode());
            stream.write(0);
        } else {
            stream.write(new VarInt(bits.length).encode());
            stream.write(bits);
        }
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput output : outputs) {
            // TODO: Allow these to be specified, if one day we care about sending this message ourselves
            // (currently it's just used for unit testing).
            Utils.uint32ToByteStreamLE(0L, stream);  // Version
            Utils.uint32ToByteStreamLE(0L, stream);  // Height
            output.bitcoinSerializeToStream(stream);
        }
    }

    @Override
    void parse() throws ProtocolException {
        // Format is:
        //   uint32 chainHeight
        //   uint256 chainHeadHash
        //   vector<unsigned char> hitsBitmap;
        //   vector<CCoin> outs;
        //
        // A CCoin is  { int nVersion, int nHeight, CTxOut output }
        // The bitmap indicates which of the requested TXOs were found in the UTXO set.
        height = readUint32();
        chainHead = readHash();
        int numBytes = (int) readVarInt();
        if (numBytes <= 0 || numBytes > InventoryMessage.MAX_INVENTORY_ITEMS / 8)
            throw new ProtocolException("hitsBitmap out of range: " + numBytes);
        byte[] hitsBytes = readBytes(numBytes);
        hitMap = BitSet.valueOf(hitsBytes);
        int numOuts = (int) readVarInt();
        if (numOuts < 0 || numOuts > InventoryMessage.MAX_INVENTORY_ITEMS)
            throw new ProtocolException("numOuts out of range: " + numOuts);
        outputs = new ArrayList<TransactionOutput>(numOuts);
        heights = new long[numOuts];
        for (int i = 0; i < numOuts; i++) {
            long version = readUint32();
            long height = readUint32();
            if (version > 1)
                throw new ProtocolException("Unknown tx version in getutxo output: " + version);
            TransactionOutput output = new TransactionOutput(params, null, payload, cursor);
            outputs.add(output);
            heights[i] = height;
            cursor += output.length;
        }
        length = cursor;
    }

    @Override
    protected void parseLite() throws ProtocolException {
        // Not used.
    }

    public BitSet getHitMap() {
        return hitMap;
    }

    public List<TransactionOutput> getOutputs() {
        return new ArrayList<TransactionOutput>(outputs);
    }

    public long[] getHeights() { return heights; }

    @Override
    public String toString() {
        return "UTXOSMessage{" +
                "height=" + height +
                ", chainHead=" + chainHead +
                ", hitMap=" + hitMap +
                ", outputs=" + outputs +
                ", heights=" + Arrays.toString(heights) +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        UTXOSMessage message = (UTXOSMessage) o;

        if (height != message.height) return false;
        if (!chainHead.equals(message.chainHead)) return false;
        if (!Arrays.equals(heights, message.heights)) return false;
        if (!hitMap.equals(message.hitMap)) return false;
        if (!outputs.equals(message.outputs)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = (int) (height ^ (height >>> 32));
        result = 31 * result + chainHead.hashCode();
        result = 31 * result + hitMap.hashCode();
        result = 31 * result + outputs.hashCode();
        result = 31 * result + Arrays.hashCode(heights);
        return result;
    }
}
