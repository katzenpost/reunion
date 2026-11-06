// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"

	"github.com/katzenpost/hpqc/util"

	"github.com/katzenpost/reunion"
)

type State interface {
	StoreT1(context *[32]byte, id *[32]byte, t1 []byte) error
	StoreT2(context *[32]byte, id *[32]byte, t2 []byte) error
	StoreT3(context *[32]byte, id *[32]byte, t3 []byte) error
	QueryT1(context *[32]byte, id *[32]byte) ([][]byte, error)
	QueryT2(context *[32]byte, id *[32]byte) ([][]byte, error)
	QueryT3(context *[32]byte, id *[32]byte) ([][]byte, error)
}

func isSane(request *reunion.ReunionRequest) error {
	if util.CtIsZero(request.Context[:]) {
		return errors.New("request.Context is nil")
	}
	if util.CtIsZero(request.ID[:]) {
		return errors.New("request.ID is nil")
	}
	if request.T1 != nil && request.T2 != nil && request.T3 != nil {
		return errors.New("request must not set more than T message")
	}
	if request.T1 != nil && request.T2 != nil {
		return errors.New("request must not set more than T message")
	}
	if request.T1 != nil && request.T3 != nil {
		return errors.New("request must not set more than T message")
	}
	if request.T2 != nil && request.T3 != nil {
		return errors.New("request must not set more than T message")
	}
	return nil
}

type Server struct {
	state State
}

func (s *Server) ProcessQuery(request *reunion.ReunionRequest) (*reunion.ReunionResponse, error) {

	err := isSane(request)
	if err != nil {
		return nil, err
	}

	switch {
	case request.T1 != nil:
		err = s.state.StoreT1(request.Context, request.ID, request.T1)
		if err != nil {
			return nil, err
		}
		t1s, err := s.state.QueryT1(request.Context, request.ID)
		if err != nil {
			return nil, err
		}
		return &reunion.ReunionResponse{
			ID:        request.ID,
			ErrorCode: 0,
			T1s:       t1s,
		}, nil
	case request.T2 != nil:
		err = s.state.StoreT2(request.Context, request.ID, request.T2)
		if err != nil {
			return nil, err
		}
		t2s, err := s.state.QueryT2(request.Context, request.ID)
		if err != nil {
			return nil, err
		}
		return &reunion.ReunionResponse{
			ID:        request.ID,
			ErrorCode: 0,
			T2s:       t2s,
		}, nil
	case request.T3 != nil:
		err = s.state.StoreT3(request.Context, request.ID, request.T3)
		if err != nil {
			return nil, err
		}
		t3s, err := s.state.QueryT3(request.Context, request.ID)
		if err != nil {
			return nil, err
		}
		return &reunion.ReunionResponse{
			ID:        request.ID,
			ErrorCode: 0,
			T3s:       t3s,
		}, nil
	default:
		return nil, errors.New("invalid query")
	}

	// not reached
}
