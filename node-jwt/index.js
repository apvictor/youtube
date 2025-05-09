import express from "express"
import jwt from 'jsonwebtoken';
import users from './mocks.json' with { type: "json" };

const app = express();

app.use(express.json());

// endpoint /login
app.post('/login', async (request, response) => {
  const { email, password } = request.body;

  const user = users.find(u => u.email === email && u.password === password);

  if (!user) return response.status(401).send('Credenciais inválidas');

  const token = jwt.sign({ email: user.email }, 'DEVARMANDO', { expiresIn: '1h' });

  console.log(token);

  return response.json({ token });
});

// middleware
function authMiddleware(request, response, next) {
  const token = request.headers.authorization;

  if (!token) return response.status(401).send('Token ausente');

  try {
    const decoded = jwt.verify(token, 'DEVARMANDO');
    request.headers['user'] = decoded;
    next();
  } catch {
    return response.status(401).send('Token inválido');
  }
}

// endpoint /profile
app.get('/profile', authMiddleware, (request, response) => {
  const user = request.headers.user
  return response.send(`Bem-vindo, ${user.email}`);
});

app.listen(3000, () => console.log('Servidor rodando na porta 3000'));