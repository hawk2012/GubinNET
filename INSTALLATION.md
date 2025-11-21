# Node.js Website Constructor Installation

## Prerequisites

- Node.js (v16 or higher)
- npm (v8 or higher)

## Installation Steps

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Install dependencies:
```bash
npm install
```

This will install all necessary packages:
- express: Web framework
- ejs: Template engine
- body-parser: Request parsing middleware
- multer: File upload handling
- better-sqlite3: SQLite database driver
- cors: Cross-origin resource sharing
- vite: Build tool
- nodemon: Development server (dev dependency)

3. Start the development server:
```bash
npm run dev
```

4. For production:
```bash
npm start
```

## Configuration

The application will create a SQLite database file named `constructor.db` automatically.

## Available Scripts

- `npm start` - Start the production server
- `npm run dev` - Start the development server with hot reload
- `npm run build` - Build the frontend assets
- `npm run setup` - Install dependencies