package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

const Version = 1

type Request struct {
	Version int    `json:"version"`
	Command string `json:"command"`
}
type Response struct {
	Version int    `json:"version"`
	Result  any    `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
}

func Read(conn net.Conn) (Request, error) {
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	decoder := json.NewDecoder(io.LimitReader(conn, 4096))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	if request.Version != Version {
		return request, errors.New("unsupported IPC version")
	}
	return request, nil
}

func Send(conn net.Conn, result any, err error) error {
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	response := Response{Version: Version, Result: result}
	if err != nil {
		response.Error = err.Error()
	}
	return json.NewEncoder(conn).Encode(response)
}

func Call(ctx context.Context, directory, command string) (json.RawMessage, error) {
	conn, err := dial(ctx, directory, false)
	if err != nil && ReadOnly(command) {
		var statusErr error
		conn, statusErr = dial(ctx, directory, true)
		if statusErr == nil {
			err = nil
		} else {
			err = errors.Join(err, statusErr)
		}
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(Request{Version, command}); err != nil {
		return nil, err
	}
	var response struct {
		Version int             `json:"version"`
		Result  json.RawMessage `json:"result"`
		Error   string          `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(conn, 8<<20)).Decode(&response); err != nil {
		return nil, err
	}
	if response.Version != Version {
		return nil, errors.New("unsupported IPC response version")
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	return response.Result, nil
}

func ReadOnly(command string) bool {
	return command == "status" || command == "dns-status" || command == "geo-status"
}
