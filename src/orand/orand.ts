import { enc } from 'crypto-js';
import axios, { AxiosResponse } from 'axios';
import { OrandHmac } from './hmac';

export interface IOrandEpoch {
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
}

export interface IOrandEpochProof {
  y: string;
  gamma: [string, string];
  c: string;
  s: string;
  uWitness: string;
  cGammaWitness: [string, string];
  sHashWitness: [string, string];
  zInv: string;
}

export interface IOrandConfig {
  url: string;
  user: string;
  secretKey: string;
  chainId: number;
  consumerAddress: string;
}

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

function objectToCamelCase(obj: any): any {
  let keys = Object.keys(obj);
  let camelResult: any = {};
  for (let i = 0; i < keys.length; i += 1) {
    camelResult[toCamelCase(keys[i])] = obj[keys[i]];
  }
  return camelResult;
}

export class Orand {
  private url: string;
  private user: string;
  private hmac: OrandHmac;
  private chainId: number;
  private consumerAddress: string;

  // Construct a new instance of Orand
  constructor(config: Partial<IOrandConfig> = {}) {
    this.url = config.url || 'http://localhost:1337';
    this.hmac = new OrandHmac(config.secretKey || '0x00');
    this.user = config.user || '';
    this.chainId = config.chainId || 0;
    this.consumerAddress = config.consumerAddress || '0x0000000000000000000000000000000000000000';
  }

  private authorization(): string {
    /*const header = enc.Utf8.parse(
      JSON.stringify({
        alg: 'HS256',
        typ: 'JWT',
      }),
    );*/
    const payload = enc.Utf8.parse(
      JSON.stringify({
        user: this.user,
        nonce: (Math.random() * 0xffffffff) >>> 0,
        timestamp: Date.now(),
      }),
    );
    const signature = this.hmac.sign(payload);
    return `bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${enc.Base64url.stringify(payload)}.${enc.Base64url.stringify(
      signature,
    )}`;
  }

  private async _request(
    method: string,
    params: string[],
    authorization: boolean = true,
  ): Promise<AxiosResponse<any, any>> {
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
        params,
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
  public async newPrivateEpoch(): Promise<IOrandEpoch> {
    return <IOrandEpoch>(
      this._postProcess(await this._request('orand_newPrivateEpoch', [this.chainId.toString(), this.consumerAddress]))
    );
  }

  public transformProof(proof: IOrandEpoch): [string, IOrandEpochProof] {
    return [
      `0x${proof.signatureProof}`,
      {
        y: `0x${proof.y}`,
        gamma: [`0x${proof.gamma.substring(0, 64)}`, `0x${proof.gamma.substring(64, 128)}`],
        c: `0x${proof.c}`,
        s: `0x${proof.s}`,
        uWitness: `0x${proof.witnessAddress}`,
        cGammaWitness: [`0x${proof.witnessGamma.substring(0, 64)}`, `0x${proof.witnessGamma.substring(64, 128)}`],
        sHashWitness: [`0x${proof.witnessHash.substring(0, 64)}`, `0x${proof.witnessHash.substring(64, 128)}`],
        zInv: `0x${proof.inverseZ}`,
      },
    ];
  }

  // Not required authentication
  public async getPrivateEpoch(epoch: number): Promise<IOrandEpoch[]> {
    return <IOrandEpoch[]>(
      this._postProcess(
        await this._request(
          'orand_getPrivateEpoch',
          [this.chainId.toString(), this.consumerAddress, epoch.toString()],
          false,
        ),
      )
    );
  }

  // Not required authentication
  public async getPublicEpoch(epoch: number): Promise<IOrandEpoch[]> {
    return <IOrandEpoch[]>(
      this._postProcess(await this._request('orand_getPublicEpoch', [this.chainId.toString(), epoch.toString()], false))
    );
  }

  // Not required authentication
  public async getPublicKey(user?: string): Promise<IOrandEpoch[]> {
    return <IOrandEpoch[]>(
      this._postProcess(
        await this._request('orand_getPublicKey', [typeof user === 'undefined' ? this.user : user], false),
      )
    );
  }
}
