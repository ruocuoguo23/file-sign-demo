package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/verifier"
	"os"

	"github.com/openpubkey/openpubkey/client"
)

type FileSigner struct {
	op           client.OpenIdProvider
	pkRecordPath string
	sigPath      string
	pktPath      string
}

func NewFileSigner(op client.OpenIdProvider, pkRecordPath, sigPath, pktPath string) *FileSigner {
	return &FileSigner{op, pkRecordPath, sigPath, pktPath}
}

func (fs *FileSigner) Sign(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	digest := sha256.Sum256(data)

	pktJson, sig, err := Sign(fs.op, digest[:], fs.pkRecordPath)
	if err != nil {
		return err
	}

	if err := os.WriteFile(fs.sigPath, sig, 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}
	if err := os.WriteFile(fs.pktPath, pktJson, 0644); err != nil {
		return fmt.Errorf("failed to write pktJson: %w", err)
	}
	fmt.Println("File signed successfully.")
	return nil
}

func (fs *FileSigner) Verify(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	digest := sha256.Sum256(data)

	sig, err := os.ReadFile(fs.sigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}
	pktJson, err := os.ReadFile(fs.pktPath)
	if err != nil {
		return fmt.Errorf("failed to read pktJson: %w", err)
	}

	return Verify(fs.op, pktJson, sig, digest[:], fs.pkRecordPath)
}

func Sign(op client.OpenIdProvider, message []byte, pkRecordPath string) ([]byte, []byte, error) {
	opkClient, err := client.New(op)
	if err != nil {
		return nil, nil, err
	}

	pkt, pkRecord, err := opkClient.AuthWithPKRecord(context.Background())
	if err != nil {
		return nil, nil, err
	}

	// Save the public key record to the specified file
	if err := savePKRecord(pkRecord, pkRecordPath); err != nil {
		return nil, nil, fmt.Errorf("failed to save public key record: %w", err)
	}

	signedMsg, err := pkt.NewSignedMessage(message, opkClient.GetSigner())
	if err != nil {
		return nil, nil, err
	}

	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, nil, err
	}
	return pktJson, signedMsg, nil
}

func Verify(op client.OpenIdProvider, pktJson []byte, signedMsg []byte, originMsg []byte, pkRecordPath string) error {
	pkt := new(pktoken.PKToken)
	err := json.Unmarshal(pktJson, &pkt)
	if err != nil {
		return err
	}

	pktVerifier, err := verifier.New(op)
	if err != nil {
		return err
	}
	err = pktVerifier.VerifyPKTokenWithCachedKey(context.Background(), pkt, pkRecordPath)
	if err != nil {
		return err
	}

	msg, err := pkt.VerifySignedMessage(signedMsg)
	if err != nil {
		return err
	}

	idtClaims := new(oidc.OidcClaims)
	if err := json.Unmarshal(pkt.Payload, idtClaims); err != nil {
		return err
	}

	// Check if the original message matches the signed message
	if string(msg) != string(originMsg) {
		fmt.Printf("Original message: %s\n", string(originMsg))
		fmt.Printf("Signed message: %s\n", string(msg))
		return fmt.Errorf("original message does not match signed message")
	}

	fmt.Printf("Verification successful: %s (%s) signed the message '%s'\n", idtClaims.Email, idtClaims.Issuer, string(msg))

	return nil
}

func savePKRecord(pk *discover.PublicKeyRecord, filePath string) error {
	// Convert the crypto.PublicKey to a JWK format
	jwkKey, err := jwk.FromRaw(pk.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key to JWK: %w", err)
	}

	// Set metadata fields
	_ = jwkKey.Set(jwk.AlgorithmKey, pk.Alg)
	_ = jwkKey.Set("issuer", pk.Issuer)

	// Marshal the JWK to JSON
	data, err := json.MarshalIndent(jwkKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Write to the specified file path
	return os.WriteFile(filePath, data, 0644)
}
