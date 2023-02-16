import { HmacSHA256, enc, lib } from 'crypto-js';

export class OrandHmac {
  private secretKey: lib.WordArray;

  // Init a instance of OrandHmac
  // Key need to be a hex string or based64
  constructor(secretKey: string) {
    if (/^(0x|)[0-9a-f]+$/gi.test(secretKey)) {
      this.secretKey = enc.Hex.parse(secretKey.replace(/^0x/gi, ''));
    } else {
      this.secretKey = enc.Base64.parse(secretKey);
    }
  }

  // Sign message with a secret key
  public sign(message: string | lib.WordArray): lib.WordArray {
    return HmacSHA256(message, this.secretKey);
  }

  public isSignable(): boolean {
    return this.secretKey.words.length > 1;
  }
}
