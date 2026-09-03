const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// Leitura segura via variáveis de ambiente
const JWT_SECRET = process.env.JWT_SECRET || 'minha_chave_secreta_jogo_60_reais';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://okomkzwevptbdrabqymb.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable_1bRR0lQZt5Ag2POEg9IN9g_o1SC7D9y';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ROTA RAIZ
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// 1. ROTA DE CADASTRO COM CELULAR
app.post('/auth/register', async (req, res) => {
  const { name, phone, password } = req.body;

  const cleanPhone = phone ? phone.replace(/\D/g, '') : '';

  if (!cleanPhone || cleanPhone.length < 10) {
    return res.status(400).json({ error: 'Número de celular inválido.' });
  }

  if (!password || password.trim().length < 6) {
    return res
      .status(400)
      .json({
        error: 'A senha é obrigatória e deve ter pelo menos 6 caracteres.',
      });
  }

  const { data: existingUser } = await supabase
    .from('users')
    .select('id')
    .eq('phone', cleanPhone)
    .single();

  if (existingUser) {
    return res.status(400).json({ error: 'Número de celular já cadastrado.' });
  }

  const hashedPassword = await bcrypt.hash(password, 8);

  const isAdmin =
    cleanPhone === '5581919732480' || cleanPhone === '81919732480';

  const { data: newUser, error } = await supabase
    .from('users')
    .insert([
      {
        name,
        phone: cleanPhone,
        password: hashedPassword,
        role: isAdmin ? 'ADMIN' : 'USER',
        subscription_status: isAdmin ? 'ACTIVE' : 'INACTIVE',
      },
    ])
    .select()
    .single();

  if (error) {
    return res.status(500).json({ error: 'Erro ao cadastrar usuário.' });
  }

  return res
    .status(201)
    .json({ message: 'Usuário cadastrado com sucesso!', userId: newUser.id });
});

// 2. ROTA DE LOGIN COM CELULAR
app.post('/auth/login', async (req, res) => {
  const { phone, password } = req.body;
  const cleanPhone = phone ? phone.replace(/\D/g, '') : '';

  const { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('phone', cleanPhone)
    .single();

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Celular ou senha incorretos.' });
  }

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });

  return res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      phone: user.phone,
      role: user.role,
      subscriptionStatus: user.subscription_status,
    },
  });
});

// ROTA DE SIMULAÇÃO DE PAGAMENTO
app.post('/payment/checkout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: 'Token não fornecido.' });

  const [, token] = authHeader.split(' ');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const { data: user, error } = await supabase
      .from('users')
      .update({ subscription_status: 'ACTIVE' })
      .eq('id', decoded.id)
      .select()
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    return res.json({
      message: 'Pagamento de R$ 60,00 recebido com sucesso! Assinatura ATIVA.',
      status: user.subscription_status,
    });
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido.' });
  }
});

// 3. MIDDLEWARE DE PROTEÇÃO
const requireActiveSubscription = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: 'Token não fornecido.' });

  const [, token] = authHeader.split(' ');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.id)
      .single();

    if (!user)
      return res.status(404).json({ error: 'Usuário não encontrado.' });

    if (user.role === 'ADMIN' || user.subscription_status === 'ACTIVE') {
      req.user = user;
      return next();
    }

    return res
      .status(403)
      .json({ error: 'Assinatura de R$ 60,00/mês necessária para jogar.' });
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido.' });
  }
});

// 4. ROTA PROTEGIDA DO JOGO
app.get('/game/play', requireActiveSubscription, (req, res) => {
  return res.json({
    message: 'Acesso liberado! Redirecionando para o jogo...',
    gameUrl: '/game.html',
  });
});

// 5. INICIALIZAÇÃO DO SERVIDOR (Usando a porta do ambiente do Render)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT} e conectado ao Supabase!`);
});
