// Copyright 2021 The go-drillum Authors
// This file is part of the go-drillum library.
//
// The go-drillum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-drillum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-drillum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"math/big"

	"github.com/drillum-network/go-drillum/common"
)

//go:generate go run ../../rlp/rlpgen -type StateAccount -out gen_account_rlp.go

// StateAccount is the Drillum consensus representation of accounts.
// These objects are stored in the main account trie.
type StateAccount struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // merkle root of the storage trie
	CodeHash []byte
}
