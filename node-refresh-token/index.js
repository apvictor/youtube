import express from "express";
import jwt from 'jsonwebtoken';
import users from './mocks.json' with { type: "json" };
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(cookieParser());

// Login - envia access token e refresh token em cookie nomeado pelo e-mail do usuário
app.post('/login', (request, response) => {
  const { email, password } = request.body;

  const user = users.find(u => u.email === email && u.password === password);

  if (!user) return response.status(401).send('Credenciais inválidas');

  const accessToken = jwt.sign({ name: user.name }, 'DEVARMANDO', { expiresIn: '1m' });
  const refreshToken = jwt.sign({ name: user.name }, 'DEVARMANDO_REFRESH', { expiresIn: '7d' });

  // Armazena o refresh token em cookie HttpOnly com nome único por e-mail (cuide para usar email seguro ou ID sanitizado)
  const cookieName = `refreshToken_${user.name}`;

  response.cookie(cookieName, refreshToken, {
    httpOnly: true,
    secure: false, // true em produção com HTTPS
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  return response.json({ accessToken, message: `Login feito. Refresh token em cookie: ${cookieName}` });
});

// Refresh usando cookie específico pelo e-mail
app.post('/refresh-token', (request, response) => {
  const { name } = request.body;

  if (!name) return response.status(400).send('Nome obrigatório para identificar o cookie correto');

  const cookieName = `refreshToken_${name}`;
  const refreshToken = request.cookies[cookieName];

  if (!refreshToken) return response.status(401).send('Refresh token ausente ou errado');

  try {
    const decoded = jwt.verify(refreshToken, 'DEVARMANDO_REFRESH');
    const accessToken = jwt.sign({ name: decoded.name }, 'DEVARMANDO', { expiresIn: '1m' });
    return response.json({ accessToken });
  } catch {
    return response.status(403).send('Refresh token inválido ou expirado');
  }
});

// Logout - remove cookie específico por e-mail
app.post('/logout', (request, response) => {
  const { name } = request.body;
  if (!name) return response.status(400).send('Email obrigatório');

  const cookieName = `refreshToken_${name}`;
  response.clearCookie(cookieName);
  return response.send(`Logout realizado para ${name}`);
});

// Middleware de proteção com access token
function authMiddleware(request, response, next) {
  const authorization = request.headers.authorization;

  if (!authorization) return response.status(401).send('Token ausente');

  const token = authorization.replace('Bearer ', '');

  console.log(request.cookies);

  try {
    const decoded = jwt.verify(token, 'DEVARMANDO');
    request.user = decoded;
    next();
  } catch {
    return response.status(401).send('Token inválido ou expirado');
  }
}

// Endpoint protegido
app.get('/profile', authMiddleware, (request, response) => {
  const user = request.user;
  return response.send(`Bem-vindo, ${user.name}`);
});

app.listen(3000, () => console.log('Servidor rodando na porta 3000'));
