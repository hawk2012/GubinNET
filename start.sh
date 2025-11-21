#!/bin/bash

# Start the Node.js Website Constructor

echo "Starting Node.js Website Constructor..."

# Install dependencies if not already installed
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

# Start the server
echo "Starting server..."
node server.js