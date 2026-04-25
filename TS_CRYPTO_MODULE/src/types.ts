export interface UserInfo {
  username: string;
  key: string;
}

export interface CipherObject{
  data : Uint8Array;
  file_type: string;
  recipients: UserInfo[];
}

interface SymmetricMetadata {
  cipher: string;
  key_size_bits: number;
  nonce_size_bytes: number;
  tag_size_bytes: number;
}

interface AsymmetricMetadata {
  cipher: string;
  key_size_bits: number;
  public_exponent: number;
  hash: string;
  mgf: string;
}

export interface KeyWrap{
  username: string,
  ephimeralPub: string,
  wrapNonce: string,
  wrappedKey: string
}

export interface EncryptionMetadata {
  encryption: string;
  symmetric: SymmetricMetadata;
  asymmetric: AsymmetricMetadata;
  nonce: string;
  recipients: UserInfo[];
  file_type: string;
  timestamp: string;
}