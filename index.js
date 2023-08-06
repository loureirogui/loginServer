
require('dotenv').config();
const { secretKey, dbConfig } = require('./config');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());



// Configuração da conexão com o banco de dados MySQL
const db = mysql.createConnection(dbConfig);

// Rota de login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Verifique se o usuário existe no banco de dados
  const sql = 'SELECT * FROM user WHERE email = ?';
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.log('Erro ao buscar usuário:', err.message);
      return res.status(500).end();
    }

    if (results.length === 0) {
      console.log('Usuário não encontrado');
      return res.status(401).end();
    }

    const user = results[0];

    // Comparar a senha digitada pelo usuário com o valor armazenado no banco de dados
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error('Erro ao comparar senhas:', err);
        return res.status(500).end();
      }

      if (result) {
        // Crie um token JWT e envie-o de volta para o cliente
        const token = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: '1h' });
        console.log('Login realizado com sucesso!');
        console.log('Token:', token);
        return res.json({ token }); // Você pode enviar o token como resposta se quiser.
      } else {
        console.log('Senha incorreta');
        console.log('Valor digitado pelo usuário:', password);
        console.log('Senha armazenada no banco de dados:', user.password);
        return res.status(401).end();
      }
    });
  });
});

// Rota de cadastro de novo usuário. Não está disponível no projeto react native pois a atribuição de criar novos usuários deverá ser realizado por profissional com autorização mais alta
app.post('/signup', (req, res) => {
  const { email, password } = req.body;

  // Verifique se o usuário já existe no banco de dados
  const sqlCheckUser = 'SELECT * FROM user WHERE email = ?';
  db.query(sqlCheckUser, [email], (err, results) => {
    if (err) {
      console.log('Erro ao verificar usuário:', err.message);
      return res.status(500).end();
    }

    if (results.length > 0) {
      console.log('Usuário já existe');
      return res.status(400).json({ message: 'O email já está em uso. Por favor, escolha outro email.' });
    }

    // Hash da senha usando bcrypt
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        console.error('Erro ao gerar hash da senha:', err);
        return res.status(500).end();
      }

      // Inserir o novo usuário no banco de dados
      const sqlInsertUser = 'INSERT INTO user (email, password) VALUES (?, ?)';
      db.query(sqlInsertUser, [email, hash], (err, result) => {
        if (err) {
          console.log('Erro ao criar usuário:', err.message);
          return res.status(500).end();
        }

        // Crie um token JWT e envie-o de volta para o cliente
        const token = jwt.sign({ id: result.insertId, email }, secretKey, { expiresIn: '1h' });
        console.log('Conta criada com sucesso!');
        console.log('Token:', token);
        return res.json({ token }); // Você pode enviar o token como resposta se quiser.
      });
    });
  });
});

// Middleware para verificar o token em rotas protegidas
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    console.log('Token não fornecido');
    return res.status(401).end();
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.log('Token inválido');
      return res.status(401).end();
    }

    req.user = decoded;
    next();
  });
};

// Rota protegida - exemplo
app.get('/data', verifyToken, (req, res) => {
  // Você pode acessar o usuário autenticado em req.user
  console.log('Dados protegidos acessados com sucesso!');
  console.log('Usuário:', req.user);
  res.end();
});

// Inicie o servidor
const port = 5000;
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});