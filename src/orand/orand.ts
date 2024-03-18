import { enc } from 'crypto-js';
import axios, { AxiosResponse } from 'axios';
import { ContractRunner, ContractTransactionResponse, JsonRpcProvider, ethers } from 'ethers';
import type { OrandProviderV2 } from '../types/OrandProviderV2';
import { OrandHmac } from './hmac';
import abiOrandProviderV2 from '../abi/OrandProviderV2.json';

export type OrandEpoch = {
  epoch: number;
  alpha: string;
  gamma: string;
  c: string;
  s: string;
  y: string;
  witnessAddress: string;
  witnessGamma: string;
  witnessHash: string;
  inverseZ: string;
  signatureProof: string;
  createdDate: string;
};

export type VerifyEpochProofResult = {
  ecdsaProof: {
    signer: string;
    receiverAddress: string;
    receiverEpoch: bigint;
    ecvrfProofDigest: bigint;
  };
  currentEpochNumber: bigint;
  isEpochLinked: boolean;
  isValidDualProof: boolean;
  currentEpochResult: bigint;
  verifiedEpochResult: bigint;
};

export type OrandEpochProof = {
  // Skip pk since it existed on smart contract
  gamma: [string, string];
  c: string;
  s: string;
  alpha: string;
  uWitness: string;
  cGammaWitness: [string, string];
  sHashWitness: [string, string];
  zInv: string;
};

export type OrandConfig = {
  url: string;
  user: string;
  secretKey: string;
  consumerAddress: string;
};

export type RecordNetwork = {
  url: string;
  chainId: number;
  providerAddress: string;
};

export type RecordPublicKey = {
  username: string;
  publicKey: string;
  createdDate: string;
};

export type OrandProof = {
  ecdsaProof: string;
  ecvrfProof: OrandEpochProof;
};

const NETWORK_MAP = new Map<number, string>([
  // A8 Testnet
  [28122024, '0x5778CE57f49A5487D2127fd39a060D75aF694e8c'],
  // U2U Testnet
  [2484, '0xe97FE633EC2021A71214D5d9BfF9f337dD1db5c1'],
  // Mainnet
]);

function toCamelCase(caseKey: string): string {
  let ret = '';
  let flip = false;
  for (let i = 0; i < caseKey.length; i += 1) {
    const charCode = caseKey.charCodeAt(i);
    if (charCode === 95 || charCode == 45) {
      flip = true;
      continue;
    }
    ret += charCode >= 97 && charCode <= 122 && flip ? String.fromCharCode(charCode - 32) : caseKey[i];
    if (flip) {
      flip = false;
    }
  }
  return ret;
}

function paddingZero(value: string): string {
  return value.length % 2 === 0 ? value : value.padStart(value.length + 1, '0');
}

function addHexPrefix(value: string): string {
  return /^0x/gi.test(value) ? paddingZero(value) : `0x${paddingZero(value)}`;
}

function objectToCamelCase(obj: any): any {
  let keys = Object.keys(obj);
  let camelResult: any = {};
  for (let i = 0; i < keys.length; i += 1) {
    camelResult[toCamelCase(keys[i])] = obj[keys[i]];
  }
  return camelResult;
}

export class Orand {
  private static instances = new Map<string, Orand>();
  private url: string;
  private user: string;
  private hmac: OrandHmac;
  private network: RecordNetwork;
  private consumerAddress: string;
  private orandProvider: OrandProviderV2;
  private defaultRPCProvider: JsonRpcProvider;

  get rpcProvider() {
    return this.defaultRPCProvider;
  }

  get orandProviderV2() {
    return this.orandProvider;
  }

  // Construct a new instance of Orand
  private constructor(
    config: OrandConfig,
    network: RecordNetwork,
    rpcProvider: JsonRpcProvider,
    orandProvider: OrandProviderV2,
  ) {
    this.url = config.url;
    this.hmac = new OrandHmac(config.secretKey);
    this.user = config.user;
    this.consumerAddress = config.consumerAddress;
    this.defaultRPCProvider = rpcProvider;
    this.orandProvider = orandProvider;
    this.network = network;
  }

  public static async fromConfig(orandConfig: OrandConfig, networkConfig: RecordNetwork) {
    const key = `${networkConfig.url}${orandConfig.consumerAddress}${orandConfig.user}`;
    if (!Orand.instances.has(key)) {
      const provider = new ethers.JsonRpcProvider(networkConfig.url);
      const orandProvider: OrandProviderV2 = new ethers.Contract(
        networkConfig.providerAddress,
        abiOrandProviderV2,
        provider,
      ) as any;
      Orand.instances.set(key, new Orand(orandConfig, networkConfig, provider, orandProvider));
    }
    return Orand.instances.get(key)!;
  }

  public static async fromRPC(config: OrandConfig, rpcURL: string) {
    const key = `${rpcURL}${config.consumerAddress}${config.user}`;
    if (!Orand.instances.has(key)) {
      const provider = new ethers.JsonRpcProvider(rpcURL);
      const networkInfo = await provider.getNetwork();
      const providerAddress = NETWORK_MAP.get(Number(networkInfo.chainId));
      if (!providerAddress) {
        throw new Error(`Network ${networkInfo.chainId} was not supported, please email: contract@orochi.network`);
      }
      const orandProvider: OrandProviderV2 = new ethers.Contract(providerAddress, abiOrandProviderV2, provider) as any;
      Orand.instances.set(
        key,
        new Orand(
          config,
          {
            url: rpcURL,
            chainId: Number(networkInfo.chainId),
            providerAddress,
          },
          provider,
          orandProvider,
        ),
      );
    }
    return Orand.instances.get(key)!;
  }

  private authorization(): string {
    /*const header = enc.Utf8.parse(
      JSON.stringify({
        alg: 'HS256',
        typ: 'JWT',
      }),
    );*/
    const now = Math.floor(Date.now() / 1000);
    const payload = enc.Utf8.parse(
      JSON.stringify({
        user: this.user,
        nonce: (Math.random() * 0xffffffff) >>> 0,
        iat: now,
        exp: now + 30,
      }),
    );
    const signature = this.hmac.sign(payload);
    return `bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${enc.Base64url.stringify(payload)}.${enc.Base64url.stringify(
      signature,
    )}`;
  }

  private async _authorizedRequest(method: string, ...params: any[]): Promise<AxiosResponse<any, any>> {
    return this._request(method, true, ...params);
  }

  // @todo: Test method
  public async rawRequest(method: string, ...params: any[]): Promise<AxiosResponse<any, any>> {
    return this._request(method, true, ...params);
  }

  private async _request(method: string, authorization: boolean, ...params: any[]): Promise<AxiosResponse<any, any>> {
    if (authorization === true && !this.hmac.isSignable()) {
      throw new Error('Secret key of Orand HMAC was not set');
    }
    const headers = authorization
      ? {
          Authorization: this.authorization(),
          'Content-Type': 'application/json',
        }
      : {
          'Content-Type': 'application/json',
        };
    return axios.request({
      method: 'POST',
      headers,
      data: {
        method,
        params: params.map((e) => e.toString()),
      },
      url: this.url,
    });
  }

  private _postProcess(response: AxiosResponse<any, any>): any {
    if (typeof response.data === 'string') {
      response.data = JSON.parse(response.data);
    }
    if (typeof response.data === 'object' && Array.isArray(response.data)) {
      return response.data.map((e) => objectToCamelCase(e));
    } else {
      return objectToCamelCase(response.data);
    }
  }

  // Required authentication
  public async newPrivateEpoch(): Promise<OrandEpoch> {
    return <OrandEpoch>(
      this._postProcess(
        await this._authorizedRequest('orand_newPrivateEpoch', this.network.chainId.toString(), this.consumerAddress),
      )
    );
    /*
    const latestEpochs = await this.getPrivateEpoch();
    // If there is no epoch, then it's genesis
    if (latestEpochs.length === 0) {
      return <OrandEpoch>(
        this._postProcess(
          await this._authorizedRequest('orand_newPrivateEpoch', this.network.chainId.toString(), this.consumerAddress),
        )
      );
    }
    // Get total epoch on-chain
    const onChainTotalEpoch = Number(await this.orandProvider.getTotalEpoch(this.consumerAddress));
    // If on-chain total epoch is 0, then it's genesis
    if (onChainTotalEpoch === 0) {
      let result = latestEpochs.filter((e) => e.epoch === 0);
      if (result.length === 0) {
        throw new Error('Cannot find genesis epoch');
      }
      return result[0];
    }
    // If on-chain total epoch is less than or equal to latest epoch, then it's latest epoch
    if (onChainTotalEpoch <= latestEpochs[0].epoch) {
      let result = latestEpochs.filter((e) => e.epoch === onChainTotalEpoch);
      return result.length === 0 ? latestEpochs[0] : result[0];
    }
    return <OrandEpoch>(
      this._postProcess(
        await this._authorizedRequest('orand_newPrivateEpoch', this.network.chainId.toString(), this.consumerAddress),
      )
    );*/
  }

  public static transformProof(proof: OrandEpoch): OrandProof {
    return {
      ecdsaProof: addHexPrefix(proof.signatureProof),
      ecvrfProof: {
        gamma: [addHexPrefix(proof.gamma.substring(0, 64)), addHexPrefix(proof.gamma.substring(64, 128))] as [
          string,
          string,
        ],
        c: addHexPrefix(proof.c),
        s: addHexPrefix(proof.s),
        alpha: addHexPrefix(proof.alpha),
        uWitness: addHexPrefix(proof.witnessAddress),
        cGammaWitness: [
          addHexPrefix(proof.witnessGamma.substring(0, 64)),
          addHexPrefix(proof.witnessGamma.substring(64, 128)),
        ] as [string, string],
        sHashWitness: [
          addHexPrefix(proof.witnessHash.substring(0, 64)),
          addHexPrefix(proof.witnessHash.substring(64, 128)),
        ] as [string, string],
        zInv: addHexPrefix(proof.inverseZ),
      },
    };
  }

  // Not required authentication
  public async getPrivateEpoch(epoch?: number): Promise<OrandEpoch[]> {
    return <OrandEpoch[]>(
      this._postProcess(
        await this._authorizedRequest(
          'orand_getPrivateEpoch',
          this.network.chainId,
          this.consumerAddress,
          epoch ? epoch : '9223372036854775807',
        ),
      )
    );
  }

  // Not required authentication
  public async getPublicEpoch(epoch?: number): Promise<OrandEpoch[]> {
    return <OrandEpoch[]>(
      this._postProcess(
        await this._authorizedRequest(
          'orand_getPublicEpoch',
          this.network.chainId,
          epoch ? epoch : '9223372036854775807',
        ),
      )
    );
  }

  // Not required authentication
  public async getPublicKey(user: string = 'orand'): Promise<RecordPublicKey> {
    return <RecordPublicKey>(
      this._postProcess(
        await this._authorizedRequest('orand_getPublicKey', typeof user === 'undefined' ? this.user : user),
      )
    );
  }

  public async publish(proof: OrandEpoch, wallet: ContractRunner): Promise<ContractTransactionResponse> {
    const contract = this.orandProvider.connect(wallet);
    const { ecdsaProof, ecvrfProof } = Orand.transformProof(proof);

    const verifyEpoch = await this.verifyEpoch(proof);
    if (!verifyEpoch.isValidDualProof) {
      throw new Error('Invalid dual proof');
    }
    // If current epoch is 0, then it's genesis
    if (verifyEpoch.currentEpochResult === 0n) {
      return contract.genesis(ecdsaProof, ecvrfProof);
    } else {
      return contract.publish(this.consumerAddress, ecvrfProof);
    }
  }

  public async verifyEpoch(epochECVRFProof: OrandEpoch): Promise<VerifyEpochProofResult> {
    const { ecdsaProof, ecvrfProof } = Orand.transformProof(epochECVRFProof);
    const {
      ecdsaProof: { signer, receiverAddress, receiverEpoch, ecvrfProofDigest },
      currentEpochNumber,
      isEpochLinked,
      isValidDualProof,
      currentEpochResult,
      verifiedEpochResult,
    }: VerifyEpochProofResult = await this.orandProvider.verifyEpoch(ecdsaProof, ecvrfProof);
    return {
      ecdsaProof: { signer, receiverAddress, receiverEpoch, ecvrfProofDigest },
      currentEpochNumber,
      isEpochLinked,
      isValidDualProof,
      currentEpochResult,
      verifiedEpochResult,
    };
  }

  // Get chain record of active chain
  public getNetwork(): RecordNetwork {
    return this.network;
  }
}
