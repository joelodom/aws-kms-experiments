import os
import boto3

REGION = "us-east-1"

def main():
    # Get the KMS key ID from the environment variable.
    key_id = os.environ.get("KMS_KEY_ID")
    if not key_id:
        raise ValueError("Environment variable KMS_KEY_ID is not set.")
    print(f"KMS_KEY_ID is {key_id}")

    # Create a KMS client. Adjust the region as needed.
    kms = boto3.client('kms', region_name=REGION)

    # The plaintext message to encrypt.
    plaintext = b"Hello!"

    # Encrypt the plaintext using AWS KMS.
    encrypt_response = kms.encrypt(
        KeyId=key_id,
        Plaintext=plaintext
    )
    ciphertext = encrypt_response['CiphertextBlob']
    print("Encryption successful. Ciphertext: ", ciphertext)

    # Decrypt the ciphertext using AWS KMS.
    decrypt_response = kms.decrypt(
        CiphertextBlob=ciphertext
    )
    decrypted_text = decrypt_response['Plaintext']
    print("Decryption successful. Decrypted text: ", decrypted_text)

    # Verify that decryption returns the original plaintext.
    if decrypted_text == plaintext:
        print("Success: Decrypted text matches the original plaintext!")
    else:
        print("Error: Decrypted text does not match the original plaintext.")

if __name__ == "__main__":
    main()
