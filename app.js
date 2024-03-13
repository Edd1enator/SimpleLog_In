const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const db = new sqlite3.Database(':memory:');

app.set('view engine', 'ejs');
app.set('views', './views');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Crear tabla de usuarios
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)");
});


// Ruta para mostrar el formulario de registro
app.get('/register', (req, res) => {
    res.render('register');
});

// Ruta para mostrar el formulario de login
app.get('/login', (req, res) => {
    res.render('login');
});


// Registro de usuario
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
    if (err) {
      return res.status(400).send({ error: "No se pudo crear el usuario" });
    }
    res.status(201).send({ message: "Usuario creado exitosamente", userId: this.lastID });
  });
});

// Login de usuario
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).send({ error: "Error al buscar el usuario" });
    }
    if (!user) {
      return res.status(404).send({ error: "Usuario no encontrado" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (match) {
      res.send({ message: "Login exitoso" });
    } else {
      res.status(401).send({ error: "Contraseña incorrecta" });
    }
  });
});

// Iniciar el servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
