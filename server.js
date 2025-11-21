const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Database initialization (using SQLite)
const Database = require('better-sqlite3');
const db = new Database('constructor.db');

// Initialize database tables
db.exec(`
  CREATE TABLE IF NOT EXISTS websites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT UNIQUE,
    theme TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/api/websites', (req, res) => {
  const websites = db.prepare('SELECT * FROM websites ORDER BY created_at DESC').all();
  res.json(websites);
});

app.post('/api/websites', (req, res) => {
  const { name, domain, theme, content } = req.body;
  
  try {
    const stmt = db.prepare('INSERT INTO websites (name, domain, theme, content) VALUES (?, ?, ?, ?)');
    const result = stmt.run(name, domain, theme, content);
    
    res.status(201).json({
      id: result.lastInsertRowid,
      name,
      domain,
      theme,
      content
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/websites/:id', (req, res) => {
  const { id } = req.params;
  const website = db.prepare('SELECT * FROM websites WHERE id = ?').get(id);
  
  if (!website) {
    return res.status(404).json({ error: 'Website not found' });
  }
  
  res.json(website);
});

app.put('/api/websites/:id', (req, res) => {
  const { id } = req.params;
  const { name, domain, theme, content } = req.body;
  
  try {
    const stmt = db.prepare('UPDATE websites SET name = ?, domain = ?, theme = ?, content = ? WHERE id = ?');
    const result = stmt.run(name, domain, theme, content, id);
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Website not found' });
    }
    
    res.json({ id, name, domain, theme, content });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/websites/:id', (req, res) => {
  const { id } = req.params;
  const stmt = db.prepare('DELETE FROM websites WHERE id = ?');
  const result = stmt.run(id);
  
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Website not found' });
  }
  
  res.status(204).send();
});

// Serve frontend
app.use(express.static(path.join(__dirname, 'dist')));

// Handle SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});