// import { nonNullable } from '@force-bridge/x';
// import { Account } from '@force-bridge/x/dist/ckb/model/accounts';
// import { BtcAsset } from '@force-bridge/x/dist/ckb/model/asset';
// import { IndexerCollector } from '@force-bridge/x/dist/ckb/tx-helper/collector';
// import { CkbTxGenerator } from '@force-bridge/x/dist/ckb/tx-helper/generator';
// import { getOwnerTypeHash } from '@force-bridge/x/dist/ckb/tx-helper/multisig/multisig_helper';
// import { ForceBridgeCore } from '@force-bridge/x/dist/core';
// import { asyncSleep } from '@force-bridge/x/dist/utils';
// import { logger } from '@force-bridge/x/dist/utils/logger';
// import { BTCChain, getBtcMainnetFee, IBalance } from '@force-bridge/x/dist/xchain/btc';
// import { Amount } from '@lay2/pw-core';
// import bitcore from 'bitcore-lib';
// import commander from 'commander';
// import { RPCClient } from 'rpc-bitcoin';
// import { getSudtBalance, parseOptions, waitUnlockTxCompleted } from './utils';
//
// const Unit = bitcore.Unit;
//
// export const btcCmd = new commander.Command('btc');
// btcCmd
//   .command('lock')
//   .requiredOption('-p, --privateKey', 'private key of locked account')
//   .requiredOption('-u, --userAddr', 'address on btc')
//   .requiredOption('-a, --amount', 'amount to lock. unit is btc')
//   .requiredOption('-r, --recipient', 'recipient address on ckb')
//   .option('-e, --extra', 'extra data of sudt')
//   .option('-f, --feeRate', 'satoshis/byte of tx data. default value will be from https://bitcoinfees.earn.com/#fees')
//   .option('-w, --wait', 'whether waiting for transaction confirmed')
//   .action(doLock)
//   .description('lock asset on btc');
//
// btcCmd
//   .command('unlock')
//   .requiredOption('-r, --recipient', 'recipient address on btc')
//   .requiredOption('-p, --privateKey', 'private key of unlock address on ckb')
//   .requiredOption('-a, --amount', 'amount of unlock. unit is btc')
//   .option('-w, --wait', 'whether waiting for transaction confirmed')
//   .action(doUnlock)
//   .description('unlock asset on btc');
//
// btcCmd
//   .command('balanceOf')
//   .requiredOption('-addr, --address', 'address on btc or ckb')
//   .option('-o, --origin', 'whether query balance on btc')
//   .action(doBalanceOf)
//   .description('query balance of address on btc or ckb');
//
// async function doLock(
//   opts: {
//     privateKey: boolean;
//     userAddr: boolean;
//     amount: boolean;
//     recipient: boolean;
//     extra?: boolean;
//     feeRate?: boolean;
//     wait?: boolean;
//   },
//   command: commander.Command,
// ) {
//   const options = parseOptions(opts, command);
//   const privateKey = options.get('privateKey');
//   const amount = options.get('amount');
//   const userAddr = nonNullable(options.get('userAddr'));
//   const recipient = options.get('recipient');
//   const extra = options.get('extra');
//   const feeRate = options.get('feeRate');
//   const memo = nonNullable(extra === undefined ? recipient : `${recipient},${extra}`);
//   const feeRateData = await getBtcMainnetFee();
//   const txFeeRate = feeRate === undefined ? feeRateData.fastestFee : Number(feeRate);
//
//   const btcChain = new BTCChain();
//   const userPrivKey = new bitcore.PrivateKey(privateKey);
//   const lockStartHeight = await btcChain.getBtcHeight();
//   const lockTxHash = await btcChain.sendLockTxs(
//     userAddr,
//     Unit.fromBTC(amount).toSatoshis(),
//     userPrivKey,
//     memo,
//     txFeeRate,
//   );
//   logger.debug(`user ${userAddr} lock ${amount} btc. the lock tx hash is ${lockTxHash} after block ${lockStartHeight}`);
//
//   if (opts.wait) {
//     console.log('Waiting for transaction confirmed...');
//     while (true) {
//       await asyncSleep(3000);
//       const txOut = await btcChain.getTxOut(lockTxHash, 0);
//       if (txOut.confirmations >= 3) {
//         console.log(txOut);
//         break;
//       }
//       console.log('Lock success.');
//     }
//   }
// }
//
// async function doUnlock(
//   opts: { recipient: boolean; privateKey: boolean; amount: boolean; wait?: boolean },
//   command: commander.Command,
// ) {
//   const options = parseOptions(opts, command);
//   const recipientAddress = nonNullable(options.get('recipient'));
//   const privateKey = nonNullable(options.get('privateKey'));
//   const amount = options.get('amount');
//
//   const account = new Account(privateKey);
//   const generator = new CkbTxGenerator(ForceBridgeCore.ckb, ForceBridgeCore.ckbIndexer);
//   const burnAmount = new Amount(Unit.fromBTC(amount).toSatoshis(), 0);
//   const burnTx = await generator.burn(
//     await account.getLockscript(),
//     recipientAddress.toString(),
//     new BtcAsset('btc', getOwnerTypeHash()),
//     burnAmount,
//   );
//   const signedTx = ForceBridgeCore.ckb.signTransaction(privateKey)(burnTx);
//   const burnTxHash = await ForceBridgeCore.ckb.rpc.sendTransaction(signedTx);
//   console.log(
//     `Address:${account.address} unlock ${amount} , recipientAddress:${recipientAddress}, burnTxHash:${burnTxHash}`,
//   );
//
//   if (opts.wait) {
//     await waitUnlockTxCompleted(burnTxHash);
//   }
// }
//
// async function doBalanceOf(opts: { address: boolean; origin?: boolean }, command: commander.Command) {
//   const options = parseOptions(opts, command);
//   const address = nonNullable(options.get('address'));
//
//   if (opts.origin) {
//     const rpcClient = new RPCClient(ForceBridgeCore.config.btc.clientParams);
//     const liveUtxos: IBalance = await rpcClient.scantxoutset({
//       action: 'start',
//       scanobjects: [`addr(${address})`],
//     });
//     console.log(`BalanceOf address:${address} on BTC is ${liveUtxos.total_amount} btc`);
//     return;
//   }
//
//   const asset = new BtcAsset('btc', getOwnerTypeHash());
//   const balance = await getSudtBalance(address, asset);
//   console.log(`BalanceOf address:${address} on ckb is ${Unit.fromSatoshis(balance.toString(0)).toBTC()} btc`);
// }
