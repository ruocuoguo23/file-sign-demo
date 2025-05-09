// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"github.com/openpubkey/openpubkey/providers"
)

func main() {
	// set up GoogleOp with default options
	opOptions := providers.GetDefaultGoogleOpOptions()
	opOptions.GQSign = false
	op := providers.NewGoogleOpWithOptions(opOptions)

	// set up file paths
	filePath := "test/example.txt"
	pkRecordPath := "test/public_key_record.json"
	sigPath := "test/signature.bin"
	pktPath := "test/pkt.json"

	// set up file signer
	fs := NewFileSigner(op, pkRecordPath, sigPath, pktPath)

	// sign
	if err := fs.Sign(filePath); err != nil {
		fmt.Println("Sign error:", err)
		return
	}

	// verify
	if err := fs.Verify(filePath); err != nil {
		fmt.Println("Verify error:", err)
		return
	}

	fmt.Println("File signed and verified successfully!")
}
