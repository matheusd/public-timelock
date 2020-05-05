package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v2"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/decred/dcrd/dcrutil/v2"
	"github.com/decred/dcrd/txscript/v2"
	"github.com/decred/dcrd/wire"
)

func orFatal(format string, err error) {
	if err != nil {
		fmt.Printf(format, err)
		fmt.Printf("\n")
		os.Exit(1)
	}
}

func main() {
	net := chaincfg.TestNet3Params()

	privKeyBytes, err := hex.DecodeString("4d89a95c972aa547cdce5b3e477556d5244a040091fafe3a4dc57630d8317f1f")
	orFatal("Unable to decode private key bytes: %v", err)

	privKey, pubKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	pubKeyHash := dcrutil.Hash160(pubKey.Serialize())

	locktime := int64(500000)
	locktimeBytes, err := (&txscript.ScriptBuilder{}).AddInt64(locktime).Script()
	orFatal("Unable to generate locktime bytes: %v", err)
	fmt.Printf("locktime bytes: %x\n", locktimeBytes)

	// Redeem script. Publishing this in plain text means you can extract
	// the pubkey hash.
	redeemScript := []byte{
		// 0-3 locktime push
		4: txscript.OP_CHECKLOCKTIMEVERIFY,
		5: txscript.OP_DUP,
		6: txscript.OP_HASH160,
		7: txscript.OP_DATA_20,
		// 8-28 pubkey hash
		29: txscript.OP_EQUALVERIFY,
		30: txscript.OP_CHECKSIG,
	}
	copy(redeemScript[:3], locktimeBytes)
	copy(redeemScript[8:28], pubKeyHash)

	// Generate tha payable address (i.e. coins sent to this address will
	// be timelocked).
	pkScript := []byte{
		0: txscript.OP_DUP,
		1: txscript.OP_DATA_20,
		// 2-22: hash160(redeemScript)
		23: txscript.OP_EQUALVERIFY,
	}
	copy(pkScript[2:22], dcrutil.Hash160(redeemScript))
	addr, err := dcrutil.NewAddressScriptHash(pkScript, net)
	orFatal("Unable to generate address script hash: %v", err)

	// Create an address that allows message verification, using the _same_
	// pubkeyhash that is used within in the script.
	msgVerifyAddr, err := dcrutil.NewAddressPubKeyHash(pubKeyHash, net, dcrec.STEcdsaSecp256k1)
	orFatal("Unable to create msg verification addr: %v", err)

	// Create and sign a message that proves we have control over the
	// private key.
	msg := "I am the Walrus. Goo goo gjoob."
	var signMsg bytes.Buffer
	wire.WriteVarString(&signMsg, 0, "Decred Signed Message:\n")
	wire.WriteVarString(&signMsg, 0, msg)
	signMsgHash := chainhash.HashB([]byte(signMsg.Bytes()))
	sig, err := secp256k1.SignCompact(privKey, signMsgHash, true)
	orFatal("Unable to sign message: %v", err)

	// Debug stuff.
	fmt.Printf("Locktime: %d\n", locktime)
	fmt.Printf("Redeem Script: %x\n", redeemScript)
	fmt.Printf("Pk Script: %x\n", pkScript)
	fmt.Printf("Script Address: %s\n", addr.Address())
	fmt.Printf("Message Verify Addr: %s\n", msgVerifyAddr.Address())
	fmt.Printf("Message: %s\n", msg)
	fmt.Printf("Message Signature: %s\n", base64.StdEncoding.EncodeToString(sig))
}
