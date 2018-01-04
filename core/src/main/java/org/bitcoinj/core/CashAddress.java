package org.bitcoinj.core;

import org.bitcoinj.params.BCCMainNetParams;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;

public class CashAddress {
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    private NetworkParameters mNetworkParameters;
    private int[] mPayload;
    private int mVersion = 0;


    public CashAddress(Address address) {
        mNetworkParameters = address.getParameters();
        byte[] hash160 = address.getHash160();
        mPayload = new int[hash160.length];
        for (int i = 0; i < hash160.length; i++) {
            mPayload[i] = hash160[i] & 0xFF;
        }
        if (address.isP2SHAddress()) mVersion = 1;
    }

    public String encode() throws Exception {
        String prefix = mNetworkParameters.getUriScheme();
        int[]  prefixData = prefixToArray();
        int[] versionByte = new int[] {getVersionByte()};
        int[] data = concatenate(versionByte, mPayload);
        int[] payloadData = convertBits(data, 8, 5, false);
        int[] prefAndPayloadData = concatenate(prefixData, payloadData);
        int[] checksumData = concatenate(prefAndPayloadData, new int[]{0,0,0,0,0,0,0,0});
        BigInteger polymodResult = polymod(checksumData);
        int[] polymodArray = checksumToArray(polymodResult);
        int[] payload = concatenate(payloadData, polymodArray);
        String encodedPayload = encodeBase32(payload);
        return prefix+":"+encodedPayload;
    }

    private int[] checksumToArray(BigInteger checksum) {
        int[] result = new int[8];
        for (int i = 0; i < 8; i++) {
            result[i] = checksum.and(BigInteger.valueOf(31)).intValue();
            checksum = checksum.shiftRight(5);
        }
        reverse(result);
        return result;
    }

    /***
     * Derives an array from the given prefix to be used in the computation
     * of the address' checksum.
     *
     */
    private int[] prefixToArray() {
        String prefix = mNetworkParameters.getUriScheme();
        int[] result = new int[prefix.length()+1];

        for (int i = 0; i < prefix.length(); i++) {
            result[i] = prefix.charAt(i) & 31;
        }

        result[result.length-1] = 0;

        return result;
    }

    private byte getVersionByte() {
        return (byte) (mVersion << 3);
    }

    /**
     * Converts an array of integers made up of `from` bits into an
     * array of integers made up of `to` bits. The output array is
     * zero-padded if necessary, unless strict mode is true.
     * Original by Pieter Wuille: https://github.com/sipa/bech32.
     *
     * @param {Array} data Array of integers made up of `from` bits.
     * @param {number} from Length in bits of elements in the input array.
     * @param {number} to Length in bits of elements in the output array.
     * @param {bool} strict Require the conversion to be completed without padding.
     */
    private int[] convertBits(int[] data, int from, int to, boolean strict) throws Exception {
        int accumulator = 0;
        int bits = 0;
        ArrayList<Integer> result = new ArrayList<>();
        int mask = (1 << to) - 1;

        for (int value : data) {
            if (value < 0 || (value >> from) != 0) {
                throw new Exception("Invalid value: "+value);
            }

            accumulator = (accumulator << from) | value;
            bits += from;

            while(bits >= to) {
                bits -= to;
                result.add((accumulator >> bits) & mask);
            }
        }

        if (!strict) {
            if (bits > 0) {
                result.add((accumulator << (to - bits)) & mask);
            }
        } else if (bits >= from || ((accumulator << (to - bits)) & mask) != 0) {
            throw new Exception("Conversion requires padding but strict mode was used.");
        }

        int[] realResult = new int[result.size()];
        for (int i = 0; i < realResult.length; i++) {
            realResult[i] = result.get(i);
        }
        return realResult;
    }

    private BigInteger polymod(int[] data) {
        BigInteger[] GENERATOR = new BigInteger[] {
                new BigInteger("98f2bc8e61", 16),
                new BigInteger("79b76d99e2", 16),
                new BigInteger("f33e5fb3c4", 16),
                new BigInteger("ae2eabe2a8", 16),
                new BigInteger("1e4f43e470", 16)};
        BigInteger checksum = BigInteger.ONE;
        for (int value : data) {
            BigInteger topBits = checksum.shiftRight(35);
            checksum = checksum.and(new BigInteger("07ffffffff", 16)).shiftLeft(5).xor(BigInteger.valueOf(value));
            for (int i = 0; i < GENERATOR.length; ++i) {
                if (topBits.shiftRight(i).and(BigInteger.ONE).equals(BigInteger.ONE)) {
                    checksum = checksum.xor(GENERATOR[i]);
                }
            }
        }
        return checksum.xor(BigInteger.ONE);
    }

    private String encodeBase32(int[] data) throws Exception {
        StringBuilder base32 = new StringBuilder();
        for (int value : data) {
            if (0 <= value && value < 32) {
                base32.append(CHARSET.charAt(value));
            } else {
                throw new Exception("Invalid value: "+value);
            }
        }
        return base32.toString();
    }

    private static <T> T concatenate(T a, T b) {
        if (!a.getClass().isArray() || !b.getClass().isArray()) {
            throw new IllegalArgumentException();
        }

        Class<?> resCompType;
        Class<?> aCompType = a.getClass().getComponentType();
        Class<?> bCompType = b.getClass().getComponentType();

        if (aCompType.isAssignableFrom(bCompType)) {
            resCompType = aCompType;
        } else if (bCompType.isAssignableFrom(aCompType)) {
            resCompType = bCompType;
        } else {
            throw new IllegalArgumentException();
        }

        int aLen = Array.getLength(a);
        int bLen = Array.getLength(b);

        @SuppressWarnings("unchecked")
        T result = (T) Array.newInstance(resCompType, aLen + bLen);
        System.arraycopy(a, 0, result, 0, aLen);
        System.arraycopy(b, 0, result, aLen, bLen);

        return result;
    }

    private static void reverse(int[] data) {
        for (int left = 0, right = data.length - 1; left < right; left++, right--) {
            // swap the values at the left and right indices
            int temp = data[left];
            data[left]  = data[right];
            data[right] = temp;
        }
    }

    public static void main(String[] args) {
        Address address = Address.fromBase58(BCCMainNetParams.get(), "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw");
        CashAddress cashAddress = new CashAddress(address);
        try {
            System.out.println(cashAddress.encode());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
