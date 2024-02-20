const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const session = require('express-session');

const PORT = 3000;

const app = express();
const db = new sqlite3.Database('./db/database.db');

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
}));

db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)');
});

function validateEmail(email) {
    return /^[^@]+@\w+(\.\w+)+\w$/.test(email);
}

function validatePassword(password) {
    return password.length >= 6 && /[a-zA-Z]/.test(password) && /\d/.test(password);
}

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!validateEmail(username) || !validatePassword(password)) {
        return res.status(400).json({ error: 'Invalid email or password format.' });
    }
    const hashedPassword = bcrypt.hashSync(password, 8);

    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
        if (err) {
            return res.status(500).json({ error: 'Error registering new user, perhaps the username is already taken.' });
        }
        fs.writeFile('.\\db\\files\\' + username + '.txt', "print('Hello, world')", (err) => {
            if (err) {
                return res.status(500).send('Error creating file');
            }
        });
        res.json({ message: 'User registered successfully!' });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) return res.status(500).json({ error: 'Error on the server.' });
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(404).json({ error: 'User not found or password incorrect.' });
        }
        req.session.loggedin = true;
        req.session.username = username;
        res.json({ message: 'User logged in successfully!', username });
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ message: 'User logged out successfully.' });
    });
});

app.post('/deleteuser', (req, res) => {
    if (req.session.loggedin) {
        const username = req.session.username;
        db.run('DELETE FROM users WHERE username = ?', [username], function (err) {
            if (err) {
                return res.status(500).json({ error: 'Error deleting user.' });
            }
            fs.unlink(`.\\db\\files\\${username}.txt`, (err) => {});
            req.session.destroy(() => {
                res.json({ message: 'User deleted successfully.' });
            });
        });
    } else {
        res.status(400).json({ error: 'User is not logged in.' });
    }
});

app.get('/check', (req, res) => {
    if (req.session.loggedin) {
        res.json({ loggedin: true, username: req.session.username });
    } else {
        res.json({ loggedin: false });
    }
});


app.get('/load', (req, res) => {
    const filename = req.session.username ? `.\\db\\files\\${req.session.username}.txt` : 'notepad.txt';
    fs.readFile(filename, 'utf8', (err, data) => {
      if (err) {
        return res.status(500).send('Error reading file');
      }
      res.send(data);
    });
  });
  
app.post('/save', (req, res) => {
  const { text } = req.body;
  const filename = req.session.username ? `.\\db\\files\\${req.session.username}.txt` : 'notepad.txt';
  fs.writeFile(filename, text, err => {
    if (err) {
      return res.status(500).send('Error saving file');
    }
    res.send('File saved successfully');
  });
});


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
