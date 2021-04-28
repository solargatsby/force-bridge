import { Address, Amount, HashType, Script } from '@lay2/pw-core';
import { Cell, HexString, Script as LumosScript } from '@ckb-lumos/base';
import { Asset, ChainType } from '../model/asset';
import { logger } from '@force-bridge/utils/logger';
import { ScriptType } from '@force-bridge/ckb/tx-helper/indexer';
import { IndexerCollector } from '@force-bridge/ckb/tx-helper/collector';
import { fromHexString, stringToUint8Array, toHexString, bigintToSudtAmount, asyncSleep } from '@force-bridge/utils';
import { ForceBridgeCore } from '@force-bridge/core';
import { SerializeRecipientCellData } from '@force-bridge/ckb/tx-helper/generated/eth_recipient_cell';
import { CellCollector, Indexer } from '@ckb-lumos/indexer';
import { generateAddress, TransactionSkeleton, TransactionSkeletonType } from '@ckb-lumos/helpers';
import { common } from '@ckb-lumos/common-scripts';
import { multisigArgs, serializeMultisigScript } from '@ckb-lumos/common-scripts/lib/from_info';
import { key } from '@ckb-lumos/hd';
import { getConfig } from '@ckb-lumos/config-manager';
const CKB = require('@nervosnetwork/ckb-sdk-core').default;

const config = getConfig();
const multisigTemplate = config.SCRIPTS.SECP256K1_BLAKE160_MULTISIG;
const secpTemplate = getConfig().SCRIPTS.SECP256K1_BLAKE160;

export interface MintAssetRecord {
  asset: Asset;
  amount: Amount;
  recipient: Address;
}

function getMultisigLock() {
  const multisigScript = ForceBridgeCore.config.ckb.multisigScript;
  const serializedMultisigScript = serializeMultisigScript(multisigScript);
  const args = multisigArgs(serializedMultisigScript);
  const multisigLockScript = {
    code_hash: multisigTemplate.CODE_HASH,
    hash_type: multisigTemplate.HASH_TYPE,
    args,
  };
  return multisigLockScript;
}
function getMultisigAddr(): string {
  const multisigLockScript = getMultisigLock();
  return generateAddress(multisigLockScript);
}

function getFromAddr(): string {
  const fromPrivateKey = ForceBridgeCore.config.ckb.fromPrivateKey;
  const fromBlake160 = key.publicKeyToBlake160(key.privateToPublic(fromPrivateKey as HexString));
  const fromLockScript = {
    code_hash: secpTemplate.CODE_HASH,
    hash_type: secpTemplate.HASH_TYPE,
    args: fromBlake160,
  };
  return generateAddress(fromLockScript);
}

export class CkbTxGenerator {
  constructor(private ckb: typeof CKB, private collector: IndexerCollector) {}

  sudtDep = {
    out_point: {
      tx_hash: ForceBridgeCore.config.ckb.deps.sudtType.cellDep.outPoint.txHash,
      index: ForceBridgeCore.config.ckb.deps.sudtType.cellDep.outPoint.index,
    },
    dep_type: ForceBridgeCore.config.ckb.deps.sudtType.cellDep.depType,
  };

  bridgeLockDep = {
    out_point: {
      tx_hash: ForceBridgeCore.config.ckb.deps.bridgeLock.cellDep.outPoint.txHash,
      index: ForceBridgeCore.config.ckb.deps.bridgeLock.cellDep.outPoint.index,
    },
    dep_type: ForceBridgeCore.config.ckb.deps.bridgeLock.cellDep.depType,
  };

  async fetchMultisigCell(indexer: Indexer, maxTimes: number): Promise<Cell> {
    const cellCollector = new CellCollector(indexer, {
      type: ForceBridgeCore.config.ckb.multisigType,
    });
    let index = 0;
    while (true) {
      if (index > maxTimes) {
        throw new Error('failed to fetch multisig cell.');
      }
      for await (const cell of cellCollector.collect()) {
        if (cell != undefined) {
          return cell;
        }
      }
      logger.debug('try to fetch multisig cell: ', index++);
      await asyncSleep(1000);
    }
  }

  async fetchBridgeCell(bridgeLock: LumosScript, indexer: Indexer, maxTimes: number): Promise<Cell> {
    const cellCollector = new CellCollector(indexer, {
      lock: bridgeLock,
    });
    let index = 0;
    while (true) {
      if (index > maxTimes) {
        throw new Error('failed to fetch bridge cell.');
      }
      for await (const cell of cellCollector.collect()) {
        if (cell != undefined) {
          return cell;
        }
      }
      logger.debug('try to fetch bridge cell: ', index++);
      await asyncSleep(1000);
    }
  }

  async createBridgeCell(scripts: any[], indexer: Indexer): Promise<TransactionSkeletonType> {
    const fromAddress = getFromAddr();
    let txSkeleton = TransactionSkeleton({ cellProvider: indexer });
    const multisig_cell = await this.fetchMultisigCell(indexer, 60);
    txSkeleton = await common.setupInputCell(txSkeleton, multisig_cell, ForceBridgeCore.config.ckb.multisigScript);
    const bridgeCellCapacity = 200n * 10n ** 8n;
    const bridgeOutputs = scripts.map((script) => {
      return <Cell>{
        cell_output: {
          capacity: `0x${bridgeCellCapacity.toString(16)}`,
          lock: {
            code_hash: script.codeHash,
            hash_type: script.hashType,
            args: script.args,
          },
        },
        data: '0x',
      };
    });
    logger.debug('bridgeOutputs:', JSON.stringify(bridgeOutputs, null, 2));
    txSkeleton = txSkeleton.update('outputs', (outputs) => {
      return outputs.push(...bridgeOutputs);
    });
    const needCapacity = bridgeCellCapacity * BigInt(scripts.length);
    if (needCapacity !== 0n) {
      txSkeleton = await common.injectCapacity(txSkeleton, [fromAddress], needCapacity);
    }
    const feeRate = BigInt(1000);
    txSkeleton = await common.payFeeByFeeRate(txSkeleton, [fromAddress], feeRate);
    txSkeleton = common.prepareSigningEntries(txSkeleton);
    return txSkeleton;
  }

  async mint(records: MintAssetRecord[], indexer: Indexer): Promise<TransactionSkeletonType> {
    const fromAddress = getFromAddr();
    let txSkeleton = TransactionSkeleton({ cellProvider: indexer });
    const multisigCell = await this.fetchMultisigCell(indexer, 60);
    txSkeleton = await common.setupInputCell(txSkeleton, multisigCell, ForceBridgeCore.config.ckb.multisigScript);
    txSkeleton = txSkeleton.update('cellDeps', (cellDeps) => {
      return cellDeps.push(this.sudtDep);
    });
    txSkeleton = txSkeleton.update('cellDeps', (cellDeps) => {
      return cellDeps.push(this.bridgeLockDep);
    });

    txSkeleton = await this.buildSudtOutput(txSkeleton, records);
    txSkeleton = await this.buildBridgeCellOutput(txSkeleton, records, indexer);

    const feeRate = BigInt(1000);
    txSkeleton = await common.payFeeByFeeRate(txSkeleton, [fromAddress], feeRate);
    txSkeleton = common.prepareSigningEntries(txSkeleton);
    return txSkeleton;
  }

  async buildSudtOutput(
    txSkeleton: TransactionSkeletonType,
    records: MintAssetRecord[],
  ): Promise<TransactionSkeletonType> {
    const fromAddress = getFromAddr();
    const sudtCellCapacity = 300n * 10n ** 8n;
    for (const record of records) {
      const recipientLockscript = record.recipient.toLockScript();
      const bridgeCellLockscript = {
        codeHash: ForceBridgeCore.config.ckb.deps.bridgeLock.script.codeHash,
        hashType: ForceBridgeCore.config.ckb.deps.bridgeLock.script.hashType,
        args: record.asset.toBridgeLockscriptArgs(),
      };
      const sudtArgs = this.ckb.utils.scriptToHash(<CKBComponents.Script>bridgeCellLockscript);
      const outputSudtCell = <Cell>{
        cell_output: {
          capacity: `0x${sudtCellCapacity.toString(16)}`,
          lock: {
            code_hash: recipientLockscript.codeHash,
            hash_type: recipientLockscript.hashType,
            args: recipientLockscript.args,
          },
          type: {
            code_hash: ForceBridgeCore.config.ckb.deps.sudtType.script.codeHash,
            hash_type: ForceBridgeCore.config.ckb.deps.sudtType.script.hashType,
            args: sudtArgs,
          },
        },
        data: record.amount.toUInt128LE(),
      };
      txSkeleton = txSkeleton.update('outputs', (outputs) => {
        return outputs.push(outputSudtCell);
      });
    }
    for (let i = 1; i <= records.length; i++) {
      txSkeleton = txSkeleton.update('fixedEntries', (fixedEntries) => {
        return fixedEntries.push({
          field: 'outputs',
          index: i,
        });
      });
    }
    const needCapacity = sudtCellCapacity * BigInt(records.length);
    if (needCapacity !== 0n) {
      txSkeleton = await common.injectCapacity(txSkeleton, [fromAddress], needCapacity);
    }
    return txSkeleton;
  }

  async buildBridgeCellOutput(
    txSkeleton: TransactionSkeletonType,
    records: MintAssetRecord[],
    indexer: Indexer,
  ): Promise<TransactionSkeletonType> {
    const assets = new Array(0);
    for (const record of records) {
      const bridgeCellLockscript = {
        codeHash: ForceBridgeCore.config.ckb.deps.bridgeLock.script.codeHash,
        hashType: ForceBridgeCore.config.ckb.deps.bridgeLock.script.hashType,
        args: record.asset.toBridgeLockscriptArgs(),
      };
      if (assets.indexOf(record.asset.toBridgeLockscriptArgs()) != -1) {
        continue;
      }
      assets.push(record.asset.toBridgeLockscriptArgs());
      const bridge_cell = await this.fetchBridgeCell(
        {
          code_hash: bridgeCellLockscript.codeHash,
          hash_type: bridgeCellLockscript.hashType,
          args: bridgeCellLockscript.args,
        },
        indexer,
        5,
      );
      txSkeleton = txSkeleton.update('inputs', (inputs) => {
        return inputs.push(bridge_cell);
      });
      const outputBridgeCell = <Cell>{
        cell_output: {
          capacity: bridge_cell.cell_output.capacity,
          lock: bridge_cell.cell_output.lock,
          type: bridge_cell.cell_output.type,
        },
        data: '0x',
      };
      txSkeleton = txSkeleton.update('outputs', (outputs) => {
        return outputs.push(outputBridgeCell);
      });
    }
    return txSkeleton;
  }

  /*
  table RecipientCellData {
    recipient_address: Bytes,
    chain: byte,
    asset: Bytes,
    bridge_lock_code_hash: Byte32,
    owner_lock_hash: Byte32,
    amount: Uint128,
    fee: Uint128,
  }
   */
  async burn(
    fromLockscript: Script,
    recipientAddress: string,
    asset: Asset,
    amount: Amount,
    bridgeFee?: Amount,
  ): Promise<CKBComponents.RawTransactionToSign> {
    const multisigLockScript = getMultisigLock();
    const bridgeCellLockscript = {
      codeHash: ForceBridgeCore.config.ckb.deps.bridgeLock.script.codeHash,
      hashType: ForceBridgeCore.config.ckb.deps.bridgeLock.script.hashType,
      args: asset.toBridgeLockscriptArgs(),
    };
    const args = this.ckb.utils.scriptToHash(<CKBComponents.Script>bridgeCellLockscript);
    const searchKey = {
      script: new Script(
        ForceBridgeCore.config.ckb.deps.sudtType.script.codeHash,
        args,
        HashType.data,
      ).serializeJson() as LumosScript,
      script_type: ScriptType.type,
      filter: {
        script: fromLockscript.serializeJson() as LumosScript,
      },
    };
    const sudtCells = await this.collector.collectSudtByAmount(searchKey, amount);
    if (sudtCells.length == 0) {
      throw new Error('failed to generate burn tx. the live sudt cell is not found!');
    }
    logger.debug('burn sudtCells: ', sudtCells);
    let inputCells = sudtCells;
    const ownerLockHash = this.ckb.utils.scriptToHash(<CKBComponents.Script>{
      codeHash: multisigLockScript.code_hash,
      hashType: multisigLockScript.hash_type,
      args: multisigLockScript.args,
    });
    let recipientAddr;
    if (asset.chainType == ChainType.ETH) {
      recipientAddr = fromHexString(recipientAddress).buffer;
    } else {
      recipientAddr = fromHexString(toHexString(stringToUint8Array(recipientAddress))).buffer;
    }
    const params = {
      recipient_address: recipientAddr,
      chain: asset.chainType,
      asset: fromHexString(asset.getAddress()).buffer,
      amount: fromHexString(amount.toUInt128LE()).buffer,
      bridge_lock_code_hash: fromHexString(ForceBridgeCore.config.ckb.deps.bridgeLock.script.codeHash).buffer,
      owner_lock_hash: fromHexString(ownerLockHash).buffer,
      fee: new Uint8Array(16).buffer,
    };

    const recipientCellData = `0x${toHexString(new Uint8Array(SerializeRecipientCellData(params)))}`;

    const outputs = new Array(0);
    const outputsData = new Array(0);

    const recipientTypeScript = {
      codeHash: ForceBridgeCore.config.ckb.deps.recipientType.script.codeHash,
      hashType: ForceBridgeCore.config.ckb.deps.recipientType.script.hashType,
      args: '0x',
    };
    const recipientCap = (BigInt(recipientCellData.length) + 100n) * 10n ** 8n;
    const recipientOutput = {
      lock: fromLockscript,
      type: recipientTypeScript,
      capacity: `0x${recipientCap.toString(16)}`,
    };
    outputs.push(recipientOutput);
    outputsData.push(recipientCellData);

    const total = sudtCells.map((cell) => Amount.fromUInt128LE(cell.data)).reduce((a, b) => a.add(b));
    let changeAmount = Amount.ZERO;
    const sudtCellCapacity = 300n * 10n ** 8n;
    if (total.gt(amount)) {
      changeAmount = total.sub(amount);
      const changeOutput = {
        lock: sudtCells[0].lock,
        type: sudtCells[0].type,
        capacity: `0x${sudtCellCapacity.toString(16)}`,
      };
      outputs.push(changeOutput);
      outputsData.push(changeAmount.toUInt128LE());
    } else if (total.lt(amount)) {
      throw new Error('sudt amount is not enough!');
    }
    const fee = 100000n;
    const outputCap = outputs.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
    const needSupplyCapCells = await this.collector.getCellsByLockscriptAndCapacity(
      fromLockscript,
      Amount.fromUInt128LE(bigintToSudtAmount(outputCap - sudtCellCapacity * BigInt(sudtCells.length) + fee)),
    );
    inputCells = inputCells.concat(needSupplyCapCells);
    this.handleChangeCell(inputCells, outputs, outputsData, fromLockscript, fee);

    const inputs = inputCells.map((cell) => {
      return { previousOutput: cell.outPoint, since: '0x0' };
    });

    const { secp256k1Dep } = await this.ckb.loadDeps();
    const cellDeps = [
      {
        outPoint: secp256k1Dep.outPoint,
        depType: secp256k1Dep.depType,
      },
      // sudt dep
      {
        outPoint: ForceBridgeCore.config.ckb.deps.sudtType.cellDep.outPoint,
        depType: ForceBridgeCore.config.ckb.deps.sudtType.cellDep.depType,
      },
      // recipient dep
      {
        outPoint: ForceBridgeCore.config.ckb.deps.recipientType.cellDep.outPoint,
        depType: ForceBridgeCore.config.ckb.deps.recipientType.cellDep.depType,
      },
    ];
    if (ForceBridgeCore.config.ckb.deps.pwLocks != undefined) {
      cellDeps.push({
        outPoint: ForceBridgeCore.config.ckb.deps.pwLocks.cellDep.outPoint,
        depType: ForceBridgeCore.config.ckb.deps.pwLocks.cellDep.depType,
      });
    }
    const rawTx = {
      version: '0x0',
      cellDeps,
      headerDeps: [],
      inputs,
      outputs,
      witnesses: [{ lock: '', inputType: '', outputType: '' }],
      outputsData,
    };
    logger.debug('generate burn rawTx:', rawTx);
    return rawTx;
  }

  handleChangeCell(inputCells, outputs, outputsData, userLockscript, fee): void {
    const inputCap = inputCells.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
    const outputCap = outputs.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
    const changeCellCapacity = inputCap - outputCap - fee;
    //FIXME: if changeCellCapacity < 64 * 10n ** 8n
    if (changeCellCapacity > 64n * 10n ** 8n) {
      const changeLockScript = {
        codeHash: userLockscript.codeHash,
        hashType: userLockscript.hashType,
        args: userLockscript.args,
      };
      const changeCell = {
        lock: changeLockScript,
        capacity: `0x${changeCellCapacity.toString(16)}`,
      };
      outputs.push(changeCell);
      outputsData.push('0x');
    }
  }

  async supplyCap(lockscript, inputsCell, outputs, outputsData, fee) {
    let inputCap = inputsCell.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
    const outputCap = outputs.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
    const needSupplyCapCells = await this.collector.getCellsByLockscriptAndCapacity(
      lockscript,
      Amount.fromUInt128LE(bigintToSudtAmount(outputCap - inputCap + fee)),
    );
    inputsCell = inputsCell.concat(needSupplyCapCells);
    inputCap = inputsCell.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
    const changeCellCapacity = inputCap - outputCap - fee;
    if (changeCellCapacity > 64n * 10n ** 8n) {
      const changeLockScript = {
        codeHash: lockscript.codeHash,
        hashType: lockscript.hashType,
        args: lockscript.args,
      };
      const changeCell = {
        lock: changeLockScript,
        capacity: `0x${changeCellCapacity.toString(16)}`,
      };
      outputs.push(changeCell);
      outputsData.push('0x');
    }
    return {
      inputsCell: inputsCell,
      outputs: outputs,
      outputsData: outputsData,
    };
  }
}
