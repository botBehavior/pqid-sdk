declare module "@noble/post-quantum/ml-dsa.js" {
  export interface MLDSA65KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }

  export interface MLDSA65 {
    keygen(): Promise<MLDSA65KeyPair>;
    sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
    verify(
      signature: Uint8Array,
      message: Uint8Array,
      publicKey: Uint8Array
    ): Promise<boolean>;
  }

  export const ml_dsa65: MLDSA65;
}

declare module "@noble/post-quantum/ml-kem.js" {
  export interface MLKEM768KeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }

  export interface MLKEM768Encapsulated {
    cipherText: Uint8Array;
    sharedSecret: Uint8Array;
  }

  export interface MLKEM768 {
    keygen(): Promise<MLKEM768KeyPair>;
    encapsulate(publicKey: Uint8Array): Promise<MLKEM768Encapsulated>;
    decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
  }

  export const ml_kem768: MLKEM768;
}
