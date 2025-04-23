package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/websocket"
)

// WSSPlugin реализует интерфейс Plugin
type WSSPlugin struct{}

func (p *WSSPlugin) Name() string {
	return "WSSPlugin"
}

func (p *WSSPlugin) Execute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/ws" {
		handler := websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			for {
				var message string
				if err := websocket.Message.Receive(ws, &message); err != nil {
					fmt.Println("WebSocket error:", err)
					break
				}
				fmt.Println("Received:", message)
				if err := websocket.Message.Send(ws, "Echo: "+message); err != nil {
					fmt.Println("WebSocket send error:", err)
					break
				}
			}
		})
		handler.ServeHTTP(w, r)
		return true
	}
	return false
}

func init() {
	RegisterPlugin(&WSSPlugin{})
}
