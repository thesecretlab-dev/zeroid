/**
 * ZeroID Server — EdDSA Poseidon Signing
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * Uses circomlibjs EdDSA over the BabyJubJub curve with Poseidon hash.
 * This is the same signature scheme used in the Circom circuits.
 */

// @ts-expect-error — circomlibjs lacks proper type declarations
import { buildEddsa, buildBabyjub } from 'circomlibjs';
import crypto from 'node:crypto';

let eddsaInstance: any = null;
let babyjubInstance: any = null;

/** Lazily initialize the EdDSA and BabyJubJub instances */
async function getEddsa() {
  if (!eddsaInstance) {
    eddsaInstance = await buildEddsa();
    babyjubInstance = await buildBabyjub();
  }
  return { eddsa: eddsaInstance, babyjub: babyjubInstance };
}

/** EdDSA key pair */
export interface EdDSAKeyPair {
  /** 32-byte private key as hex string */
  privateKey: string;
  /** Public key as [Fx, Fy] bigint tuple */
  publicKey: [bigint, bigint];
}

/** EdDSA signature */
export interface EdDSASignature {
  /** R8 point [x, y] */
  R8: [bigint, bigint];
  /** Scalar S */
  S: bigint;
}

/**
 * Generate a new EdDSA key pair.
 * The private key is a random 32-byte buffer.
 */
export async function generateKeyPair(): Promise<EdDSAKeyPair> {
  const { eddsa } = await getEddsa();
  const privateKeyBuf = crypto.randomBytes(32);
  const publicKey = eddsa.prv2pub(privateKeyBuf);

  return {
    privateKey: Buffer.from(privateKeyBuf).toString('hex'),
    publicKey: [
      eddsa.F.toObject(publicKey[0]),
      eddsa.F.toObject(publicKey[1]),
    ],
  };
}

/**
 * Sign a message (field element) with an EdDSA private key.
 * The message should be a Poseidon hash (single field element).
 */
export async function sign(
  privateKeyHex: string,
  message: bigint,
): Promise<EdDSASignature> {
  const { eddsa } = await getEddsa();
  const privateKeyBuf = Buffer.from(privateKeyHex, 'hex');
  const msgF = eddsa.F.e(message);

  const signature = eddsa.signPoseidon(privateKeyBuf, msgF);

  return {
    R8: [
      eddsa.F.toObject(signature.R8[0]),
      eddsa.F.toObject(signature.R8[1]),
    ],
    S: signature.S,
  };
}

/**
 * Verify an EdDSA Poseidon signature.
 */
export async function verify(
  publicKey: [bigint, bigint],
  message: bigint,
  signature: EdDSASignature,
): Promise<boolean> {
  const { eddsa } = await getEddsa();

  const pubKeyF = [
    eddsa.F.e(publicKey[0]),
    eddsa.F.e(publicKey[1]),
  ];
  const msgF = eddsa.F.e(message);
  const sigObj = {
    R8: [eddsa.F.e(signature.R8[0]), eddsa.F.e(signature.R8[1])],
    S: signature.S,
  };

  return eddsa.verifyPoseidon(msgF, sigObj, pubKeyF);
}
