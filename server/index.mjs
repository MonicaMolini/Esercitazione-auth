/* eslint-disable no-undef */
import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';

// Configurazione di multer per mantenere il file in memoria
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });


dotenv.config();
const app = express();
const PORT = 5000;
// const SECRET_KEY = 'secret_key';
const SECRET_KEY = process.env.SECRET_KEY;

app.use(express.json());
app.use(cors());

const dbPromise = open({
  filename: './server/database.sqlite',
  driver: sqlite3.Database,
});

dbPromise.then(async (db) => {
  await db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    fullname TEXT NOT NULL    
  )`);

   // Poichè dobbiamo aggiungere una colonna successivamente alla creazione della tabella, verifichiamo se prima esiste [..]
   const columnExists = await db.get(`
    SELECT 1 
    FROM pragma_table_info('users')
    WHERE name = 'profile_image'
  `);

  // [..]Se non esiste, la creiamo
  if (!columnExists) {
    await db.exec(`ALTER TABLE users ADD COLUMN profile_image BLOB`);
    console.log("Column profile_image added to users table");
  }
});

// Middleware per verificare il token JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.sendStatus(403);

    // dobbiamo verificare che il token contenga l'id dell'utente
    if (!decoded.id) {
      return res.status(403).json({ error: 'Invalid token data' });
    }
//ritorniamo i dati decodificati dal token
    req.user = { id: decoded.id, username: decoded.username };
    next();
  });
};

//logica per l'upload nel database

app.post('/upload/:id', authenticateToken, upload.single('profileImage'), async (req, res) => {
  console.log("Received file:", req.file);
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const { id } = req.params;
  console.log("Uploading for user ID:", id);
  const imageBuffer = req.file.buffer;
  
  try {
    const db = await dbPromise;
    console.log("Connected to DB, updating profile image...");
    const result = await db.run('UPDATE users SET profile_image = ? WHERE id = ?', [imageBuffer, id]);
    console.log("DB update result:", result);
    if (result.changes) {
      res.json({ message: 'Profile image updated successfully' });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Error updating profile image:', error);
    res.status(500).json({ error: 'Failed to update profile image' });
  }
});

//richiesta per ottenere l'immagine dal database
app.get('/image/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const db = await dbPromise;
    const row = await db.get('SELECT profile_image FROM users WHERE id = ?', id);
    if (!row || !row.profile_image) {
      return res.status(404).send('No image found');
    }
    res.writeHead(200, {
      'Content-Type': 'image/jpeg', // Facciamo conto che l'immagine debba essere JPEG
      'Content-Length': row.profile_image.length
    });
    res.end(row.profile_image);
  } catch (error) {
    console.error('Error fetching image:', error);
    res.status(500).send('Failed to fetch image');
  }
});


app.get('/profile/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;

  try {
    const db = await dbPromise;
    const user = await db.get('SELECT id, username, email, fullname FROM users WHERE username = ?', [username]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

app.post('/register', async (req, res) => {
  const { username, password, email, fullname } = req.body;
  if (!username || !password || !email || !fullname) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const db = await dbPromise;
    const existingUser = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    await db.run('INSERT INTO users (username, password, email, fullname) VALUES (?, ?, ?, ?)', [
      username,
      password,
      email,
      fullname,
    ]);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }

  try {
    const db = await dbPromise;
    const user = await db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
//quando creiamo il token aggiungiamo anche l'id in modo tale che possa essere decodificato
    const token = jwt.sign({id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.put('/update/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { username, password, email, fullname } = req.body;

  if (!username || !password || !email || !fullname) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const db = await dbPromise;
    const existingUser = await db.get('SELECT * FROM users WHERE id = ?', [id]);
    if (!existingUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    await db.run('UPDATE users SET username = ?, password = ?, email = ?, fullname = ? WHERE id = ?', [
      username,
      password,
      email,
      fullname,
      id,
    ]);

    res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
