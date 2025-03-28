// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package reunion

// ReunionRequest is a type for encapsulating all possible messages
// sent by clients to the Reunion service on the mixnet.
type ReunionRequest struct {

	// Context contains the one week shared random value known as the weekly SRV for Katzenpost and it can never be nil.
	Context *[32]byte

	// ID contains a random 32 byte value to uniquely identify the request
	ID *[32]byte

	// T1 field can be populated with a T1 or it can be nil.
	T1 []byte

	// T2 field can be populated with a T2 or it can be nil.
	T2 []byte

	// T3 field can be populated with a T3 or it can be nil.
	T3 []byte
}

//

// ReunionResponse is type for encapsulating all possible messages
// sent by the Reunion service to the clients via Sphinx SURB reply.
type ReunionResponse struct {
	// Context contains the one week shared random value known as the weekly SRV for Katzenpost and it can never be nil.
	Context *[32]byte

	// ID contains a random 32 byte value to uniquely identify the response that corresponds to the original ReunionRequest
	ID *[32]byte

	// ErrorCode indicates a specific error or status OK. Zero is success, one is error.
	ErrorCode uint8

	// T1 is a list of all T1 mesages on the server
	T1s [][]byte

	// T2 is a list of all T2 messages on the server
	T2s [][]byte

	// T3 is a list of all T3 messages on the server
	T3s [][]byte
}
