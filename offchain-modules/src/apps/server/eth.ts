import { BigNumber, ethers } from 'ethers';
import { ForceBridgeCore } from '@force-bridge/core';
import { logger } from '@force-bridge/utils/logger';
import { isBurnTx } from '@force-bridge/handlers/ckb';
import { RecipientCellData } from '@force-bridge/ckb/tx-helper/generated/eth_recipient_cell';
import { fromHexString, toHexString, uint8ArrayToString } from '@force-bridge/utils';
import { collectSignaturesParams } from '@force-bridge/multisig/multisig-mgr';
import { buildSigRawData } from '@force-bridge/xchain/eth/utils';
import { EthUnlockRecord } from '@force-bridge/xchain/eth';
import { Amount } from '@lay2/pw-core';
const { ecsign, toRpcSig } = require('ethereumjs-util');

export async function signEthTx(payload: collectSignaturesParams): Promise<string> {
  if ('domainSeparator' in payload.payload) {
    const msgHash = buildSigRawData(
      payload.payload.domainSeparator,
      payload.payload.typeHash,
      payload.payload.unlockRecords,
      payload.payload.nonce,
    );
    if (payload.rawData !== msgHash) {
      return;
    }
  } else {
    return 'the type should be eth';
  }

  if (!(await verifyUnlockRecord(payload.payload.unlockRecords))) {
    return;
  }

  // 1. get burn tx info which is available from ckb rpc request
  // 2. confirm the block info
  // - amount recipient codehash
  // 3. select from db
  // 4. save to database
  //FIXME: verify eth_tx payload.
  const provider = new ethers.providers.JsonRpcProvider(ForceBridgeCore.config.eth.rpcUrl);
  logger.debug('signEthTx msg: ', payload);
  const args = require('minimist')(process.argv.slice(2));
  const index = args.index;
  const privKey = ForceBridgeCore.config.eth.multiSignKeys[index];
  const wallet = new ethers.Wallet(privKey, provider);
  const { v, r, s } = ecsign(
    Buffer.from(payload.rawData.slice(2), 'hex'),
    Buffer.from(wallet.privateKey.slice(2), 'hex'),
  );
  const sigHex = toRpcSig(v, r, s);
  return sigHex.slice(2);
}

async function verifyUnlockRecord(unlockRecords: EthUnlockRecord[]): Promise<boolean> {
  try {
    for (let record of unlockRecords) {
      const burnTx = await ForceBridgeCore.ckb.rpc.getTransaction(record.ckbTxHash);
      if (burnTx.txStatus !== 'commit') {
        logger.warn(
          `ETH MultiSign Verify: the tx ${record.ckbTxHash} status is ${burnTx.txStatus} which is not confirmed`,
        );
        return false;
      }
      const recipientData = burnTx.transaction.outputsData[0];
      const cellData = new RecipientCellData(fromHexString(recipientData).buffer);
      const assetAddress = uint8ArrayToString(new Uint8Array(cellData.getAsset().raw()));
      const amount = Amount.fromUInt128LE(`0x${toHexString(new Uint8Array(cellData.getAmount().raw()))}`).toString(0);
      const recipientAddress = uint8ArrayToString(new Uint8Array(cellData.getRecipientAddress().raw()));
      if (
        assetAddress !== record.token ||
        BigNumber.from(amount) !== record.amount ||
        recipientAddress !== record.recipient
      ) {
        logger.warn(
          `ETH MultiSign Verify: the tx ${record.ckbTxHash} cell data contain : asset ${assetAddress}, amount ${amount}, recipient ${recipientAddress}`,
        );
        return false;
      }
      if (!(await isBurnTx(burnTx.transaction, cellData))) {
        logger.warn(`ETH MultiSign Verify: the tx ${record.ckbTxHash}  is not burn tx`);
        return false;
      }
    }
    return true;
  } catch (e) {
    throw new Error(`ETH MultiSign Error during verify unlock record by :` + e);
  }
}
