// SPDX-FileCopyrightText: © 2014-2021 Dave Parsons & Sam Bingner
// SPDX-License-Identifier: MIT

/*
vSMC Header Structure
=====================
Offset  Length  Struct Type Description
----------------------------------------
0x00/00 0x08/08 Q      ptr  Offset to key table
0x08/08 0x04/4  I      int  Number of private keys
0x0C/12 0x04/4  I      int  Number of public keys

vSMC Key Data Structure
Offset  Length  Struct Type Description
----------------------------------------
0x00/00 0x04/04 4s     int  Key name (byte reversed e.g. #KEY is YEK#)
0x04/04 0x01/01 B      byte Length of returned data
0x05/05 0x04/04 4s     int  Data type (byte reversed e.g. ui32 is 23iu)
0x09/09 0x01/01 B      byte Flag R/W
0x0A/10 0x06/06 6x     byte Padding
0x10/16 0x08/08 Q      ptr  Internal VMware routine
0x18/24 0x30/48 48B    byte Data

The internal VMware routines point to 4 variants:
AppleSMCHandleDefault
AppleSMCHandleNTOK
AppleSMCHandleNumKeys
AppleSMCHandleOSK
*/

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/canhlinh/go-binary-pack"
	"io/ioutil"
	"os"
)

const KeyLength = 24
const DataLength = 48
const RowLength = KeyLength + DataLength

type smcHdr struct {
	address    uintptr
	cntPublic  [4]byte
	cntPrivate [4]byte
}

type smcKey struct {
	key      string
	length   byte
	dataType string
	flag     byte
	_        [6]byte
	ptrFunc  uint8
	data     [48]byte
}

func Reverse(s string) (result string) {
	for _, v := range s {
		if v != 0 {
			result = string(v) + result
		} else {
			result = " " + result
		}
	}
	return
}

func dumpkeys(contents []byte, offset int, count int) {

	println("Offset     Name Len Type Flag FuncPtr    Data")
	println("-------    ---- --- ---- ---- -------    ----")

	// Setup struct pack string
	var keyPack = []string{"4s", "B", "4s", "B", "B", "B", "B", "B", "B", "B", "Q", "48s"}

	// Create BinaryPack object
	bp := new(binarypack.BinaryPack)

	// Loop for each count and print key
	//Last key should be OSK1
	for i := 0; i < count; i++ {
		// Unpack binary key data
		ptrCurrent := offset + (i * RowLength)
		keyRow, err := bp.UnPack(keyPack, contents[ptrCurrent:ptrCurrent+RowLength])
		if err != nil {
			println(err)
		}
		keyName := Reverse(keyRow[0].(string))
		keyLength := keyRow[1].(int)
		keyType := Reverse(keyRow[2].(string))
		keyFlag := keyRow[3].(int)
		keyFunc := keyRow[10].(int)
		//keyBytes := keyRow[11].(string)
		keyData := hex.EncodeToString([]byte(keyRow[11].(string))[0:keyLength])
		println(fmt.Sprintf("0x%08x %04s %02d  %-04s 0x%02x 0x%08x %s",
			ptrCurrent,
			keyName,
			keyLength,
			keyType,
			keyFlag,
			keyFunc,
			keyData))
	}
}

func vmx() {
	//filename := "/Users/dave/Projects/vacintosh/unlocker/tests/linux/vmware-vmx-debug"
	filename := os.Args[1]
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		println(err)
		return
	}

	println("dumpsmc")
	println("-------")
	println(fmt.Sprintf("File: %s", filename))
	println()
	var smcHeaderV0 = []byte{0xF2, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00}
	var smcHeaderV1 = []byte{0xB4, 0x01, 0x00, 0x00, 0xB0, 0x01, 0x00, 0x00}

	// Setup hex string for #KEY key
	var keyKey = []byte{0x59, 0x45, 0x4B, 0x23, 0x04, 0x32, 0x33, 0x69, 0x75}

	// Setup hex string for $Adr key
	//var adrKey = []byte{0x72, 0x64, 0x41, 0x24, 0x04, 0x32, 0x33, 0x69, 0x75}

	// Find the vSMC headers
	smcHeaderV0Offset := bytes.Index(contents, smcHeaderV0) - 8
	smcHeaderV1Offset := bytes.Index(contents, smcHeaderV1) - 8

	// Find '#KEY' keys
	smcKey0 := bytes.Index(contents, keyKey)
	smcKey1 := bytes.LastIndex(contents, keyKey)

	// Find '$Adr' key in V0 table and used to patch OSK0 & OSK1 key functions
	//smcAdr := bytes.Index(contents, adrKey)
	//println(fmt.Sprintf("0x%08x", smcAdr))

	// Print vSMC0 tables and keys
	println("appleSMCTableV0 (smc.version = '0')")
	println(fmt.Sprintf("Address      : 0x%08x", smcHeaderV0Offset))
	println("Private Key #: 0xF2/242")
	println("Public Key  #: 0xF0/240")
	println(fmt.Sprintf("Table        : 0x%08x", smcKey0))
	dumpkeys(contents, smcKey0, 242)
	println("\n")

	// Print vSMC1 tables and keys
	println("appleSMCTableV1 (smc.version = '1')")
	println(fmt.Sprintf("Address      : 0x%08x", smcHeaderV1Offset))
	println("Private Key #: 0x01B4/436")
	println("Public Key  #: 0x01B0/432")
	println(fmt.Sprintf("Table        : 0x%08x", smcKey1))
	dumpkeys(contents, smcKey1, 436)

}

func main() {
	vmx()
}
