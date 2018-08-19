
# BlockChainJ Release History

0.15.1-SNAPSHOT
 - Merge bitcoinj/master with:
 - Core Segwit support
 - checksequenceverify
sha256: 20ac7078e434e1029565a8385966e35e4547ed6934ec7250da303c590aae0faf

0.14.9
 - Update BuildCheckpoints with cash network parameters
 - Generated 1-month old BTC, tBTC, BCH checkpoints

0.14.8
 - Support reading Bitcoin Cash checkpoints.

0.14.7

bip47.5
 - Update consensus rules from bitcoinj-cash/cash-0.14

bip47.3
 - Save wallet to file in BIP47AppKit#unsafeRemoveTxHash
 - Bifurcate (clone) AbstractBitcoinNetParams into AbstractBitcoinCoreParams and AbstractBitcoinCashParams to fix peer disconnections.
 - Add BIP47AppKit#getPeerGroup.

bip47.2
 - Support packagecloud deploy
 - Refactor BIP47. Rename bip47.Wallet to BIP47AppKit

bip47.1
- Support version 2 transactions
- Set maximum # of inputs and # of outputs to 20 in each Transaction.
- Deprecate Orchid

0.14.5

bip47.6
- Fix notification transaction fees (BCH: 1 satoshi / byte, BTC: 100 satoshis / byte)

bip47.5
- Avoid npe if user attempts to delete an old Bip47 channel in bip47.Wallet#unsafeRemoveTxHash

bip47.4
- Add bip47.Wallet#unsafeRemoveTxHash and tests to remove a transaction from the wallet
- Fix isValidAddress tests

bip47.3
- Add comments to bip47 classes
- Remove start(boolean startBlockChain) from bip47.Wallet.
- bip47.Wallet#isValidAddress returns true for payment codes.
- Add unit tests for payment codes

bip47.2
- Use network's default fee in notification transaction

bip47
- Functional bip47 send and receive BTC, tBTC, BCH, tBCH