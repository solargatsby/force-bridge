// import CKB from '@nervosnetwork/ckb-sdk-core';
// import { CellDep, ConfigItem } from '@lay2/pw-core';
import { Config } from './config';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const CKB = require('@nervosnetwork/ckb-sdk-core').default;
import { CkbIndexer } from '@force-bridge/ckb/tx-helper/indexer';

// make global config and var static,
// which can be import from ForceBridgeCore
export class ForceBridgeCore {
  static config: Config;
  static ckb: typeof CKB;
  static indexer: CkbIndexer;

  async init(config: Config): Promise<ForceBridgeCore> {
    ForceBridgeCore.config = config;
    ForceBridgeCore.ckb = new CKB(config.ckb.ckbRpcUrl);
    ForceBridgeCore.indexer = new CkbIndexer(config.ckb.ckbIndexerUrl);
    return this;
  }
}