/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumber,
  BigNumberish,
  BytesLike,
  CallOverrides,
  PopulatedTransaction,
  Signer,
  utils,
} from "ethers";
import type { FunctionFragment, Result } from "@ethersproject/abi";
import type { Listener, Provider } from "@ethersproject/providers";
import type {
  TypedEventFilter,
  TypedEvent,
  TypedListener,
  OnEvent,
  PromiseOrValue,
} from "../../common";

export declare namespace IOrandStorage {
  export type ECVRFEpochProofStruct = {
    y: PromiseOrValue<BigNumberish>;
    gamma: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>];
    c: PromiseOrValue<BigNumberish>;
    s: PromiseOrValue<BigNumberish>;
    uWitness: PromiseOrValue<string>;
    cGammaWitness: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>];
    sHashWitness: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>];
    zInv: PromiseOrValue<BigNumberish>;
  };

  export type ECVRFEpochProofStructOutput = [
    BigNumber,
    [BigNumber, BigNumber],
    BigNumber,
    BigNumber,
    string,
    [BigNumber, BigNumber],
    [BigNumber, BigNumber],
    BigNumber
  ] & {
    y: BigNumber;
    gamma: [BigNumber, BigNumber];
    c: BigNumber;
    s: BigNumber;
    uWitness: string;
    cGammaWitness: [BigNumber, BigNumber];
    sHashWitness: [BigNumber, BigNumber];
    zInv: BigNumber;
  };
}

export interface OrandECVRFInterface extends utils.Interface {
  functions: {
    "verifyProof(uint256[2],uint256,(uint256,uint256[2],uint256,uint256,address,uint256[2],uint256[2],uint256))": FunctionFragment;
  };

  getFunction(nameOrSignatureOrTopic: "verifyProof"): FunctionFragment;

  encodeFunctionData(
    functionFragment: "verifyProof",
    values: [
      [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      PromiseOrValue<BigNumberish>,
      IOrandStorage.ECVRFEpochProofStruct
    ]
  ): string;

  decodeFunctionResult(
    functionFragment: "verifyProof",
    data: BytesLike
  ): Result;

  events: {};
}

export interface OrandECVRF extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  interface: OrandECVRFInterface;

  queryFilter<TEvent extends TypedEvent>(
    event: TypedEventFilter<TEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TEvent>>;

  listeners<TEvent extends TypedEvent>(
    eventFilter?: TypedEventFilter<TEvent>
  ): Array<TypedListener<TEvent>>;
  listeners(eventName?: string): Array<Listener>;
  removeAllListeners<TEvent extends TypedEvent>(
    eventFilter: TypedEventFilter<TEvent>
  ): this;
  removeAllListeners(eventName?: string): this;
  off: OnEvent<this>;
  on: OnEvent<this>;
  once: OnEvent<this>;
  removeListener: OnEvent<this>;

  functions: {
    verifyProof(
      pk: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      alpha: PromiseOrValue<BigNumberish>,
      epoch: IOrandStorage.ECVRFEpochProofStruct,
      overrides?: CallOverrides
    ): Promise<[BigNumber] & { epochResult: BigNumber }>;
  };

  verifyProof(
    pk: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
    alpha: PromiseOrValue<BigNumberish>,
    epoch: IOrandStorage.ECVRFEpochProofStruct,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  callStatic: {
    verifyProof(
      pk: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      alpha: PromiseOrValue<BigNumberish>,
      epoch: IOrandStorage.ECVRFEpochProofStruct,
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  filters: {};

  estimateGas: {
    verifyProof(
      pk: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      alpha: PromiseOrValue<BigNumberish>,
      epoch: IOrandStorage.ECVRFEpochProofStruct,
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    verifyProof(
      pk: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      alpha: PromiseOrValue<BigNumberish>,
      epoch: IOrandStorage.ECVRFEpochProofStruct,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;
  };
}
