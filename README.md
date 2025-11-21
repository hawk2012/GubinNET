# Node.js Website Constructor

This is a lightweight website constructor built with Node.js and Express. It provides a fast and efficient platform for creating websites with pre-designed templates.

## Features

- Lightweight Node.js backend
- Express.js web framework
- SQLite database for data storage
- Three pre-designed templates: Business, Portfolio, and Blog
- RESTful API for managing websites
- Vite build system for frontend assets
- EJS templating engine

## Prerequisites

- Node.js (v16 or higher)
- npm (v8 or higher)

## Installation

1. Clone the repository
2. Run `npm install` to install dependencies
3. Run `npm run dev` to start the development server

For detailed installation instructions, see [INSTALLATION.md](INSTALLATION.md).

## Usage

The constructor allows users to:
- Create new websites with custom names and domains
- Choose from pre-designed templates (Business, Portfolio, Blog)
- Manage websites through a RESTful API

## Project Structure

- `server.js` - Main server file
- `package.json` - Dependencies and scripts
- `views/` - EJS templates for the frontend
- `themes/templates/` - Website design templates
- `public/` - Static assets
- `vite.config.js` - Vite build configuration
