/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Giannis Dzegoutanis
 * Copyright 2015 Andreas Schildbach
 * Copyright 2018 the bitcoinj-cash developers
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
 *
 * This file has been modified by the bitcoinj-cash developers for the bitcoinj-cash project.
 * The original file was from the bitcoinj project (https://github.com/bitcoinj/bitcoinj).
 */

package org.bitcoinj.core;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bitcoinj.params.Networks;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;

/**
 * <p>
 * Base class for addresses, e.g. native segwit addresses ({@link SegwitAddress}) or legacy addresses ({@link LegacyAddress}).
 * </p>
 * 
 * <p>
 * Use {@link #fromString(NetworkParameters, String)} to conveniently construct any kind of address from its textual
 * form.
 * </p>
 */
public abstract class Address extends PrefixedChecksummedBytes {
    private int type = 0;

    public Address(NetworkParameters params, byte[] bytes) {
        super(params, bytes);
    }

    public String toCashAddress() {
        try {
            return new CashAddress(this).encode();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String toCopayAddress() {
        try {
            return new CopayAddress(this).encode();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static Address fromString(@Nullable NetworkParameters params, String str)
            throws AddressFormatException {
        try {
            return LegacyAddress.fromBase58(params, str);
        } catch (AddressFormatException.WrongNetwork x) {
            throw x;
        } catch (AddressFormatException x) {
            try {
                return SegwitAddress.fromBech32(params, str);
            } catch (AddressFormatException.WrongNetwork x2) {
                throw x;
            } catch (AddressFormatException x2) {
                throw new AddressFormatException(str);
            }
        }
    }

    /**
     * Get either the public key hash or script hash that is encoded in the address.
     * 
     * @return hash that is encoded in the address
     */
	public static boolean isAcceptableVersion(NetworkParameters params, int version) {
        for (int v : params.getAcceptableAddressCodes()) {
            if (version == v) {
                return true;
            }
        }
        return false;
	}

    public abstract byte[] getHash();

    /**
     * Get the type of output script that will be used for sending to the address.
     * 
     * @return type of output script
     */
	/*@Override
    public Address clone() throws CloneNotSupportedException {
        return (Address) super.clone();
    }

    // Java serialization

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeUTF(params.id);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        params = NetworkParameters.fromID(in.readUTF());
    }*/

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    @Override
    public String toString() {
        if (getParameters().getUseForkId()) {
            switch (type) {
                case 1:
                    return toCashAddress();
                case 2:
                    return toCopayAddress();
                default:
                    return super.toString();
            }
        } else {
            return super.toString();
        }
	}

    public abstract ScriptType getOutputScriptType();

    public boolean isP2SHAddress(){
        return getOutputScriptType() == Script.ScriptType.P2SH ||
                getOutputScriptType() == Script.ScriptType.P2WPKH;
    }

    public abstract int getVersion();
}
