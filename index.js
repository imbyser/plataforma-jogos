const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// Variáveis de ambiente
const JWT_SECRET = process.env.JWT_SECRET || 'minha_chave_secreta_jogo_60_reais';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://okomkzwevptbdrabqymb.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable_1bRR0lQZt5Ag2POEg9IN9g_o1SC7D9y';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Rota Raiz
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// 1. ROTA DE CADASTRO
app.post('/auth/register', async (req, res) => {
  const { name, phone, password } = req.body;
  const cleanPhone = phone ? phone.replace(/\D/g, '') : '';

  if (!cleanPhone || cleanPhone.length < 10) {
    return res.status(400).json({ error: 'Número de celular inválido.' });
  }

  if (!password || password.trim().length < 6) {
    return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });
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
  const isAdmin = cleanPhone === '5581919732480' || cleanPhone === '81919732480';

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

  return res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: newUser.id });
});

// 2. ROTA DE LOGIN
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

// 3. WEBHOOK DA KIWIFY
app.post('/webhook/kiwify', async (req, res) => {
  try {
    const { order_status, Customer } = req.body;

    if (order_status === 'paid' && Customer) {
      const rawPhone = Customer.mobile || Customer.phone || '';
      const cleanPhone = rawPhone.replace(/\D/g, '');

      if (cleanPhone) {
        await supabase
          .from('users')
          .update({ subscription_status: 'ACTIVE' })
          .eq('phone', cleanPhone);

        console.log(`✅ Assinatura ativada via Kiwify para o celular: ${cleanPhone}`);
      }
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('Erro no Webhook da Kiwify:', err);
    return res.status(500).json({ error: 'Erro interno ao processar webhook' });
  }
});

// 4. MIDDLEWARES DE PROTEÇÃO
const requireAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token não fornecido.' });

  const [, token] = authHeader.split(' ');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data: user } = await supabase.from('users').select('*').eq('id', decoded.id).single();

    if (!user || user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido.' });
  }
};

const requireActiveSubscription = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token não fornecido.' });

  const [, token] = authHeader.split(' ');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data: user } = await supabase.from('users').select('*').eq('id', decoded.id).single();

    if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });

    if (user.role === 'ADMIN' || user.subscription_status === 'ACTIVE') {
      req.user = user;
      return next();
    }

    return res.status(403).json({ error: 'Assinatura ativa necessária para jogar.' });
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido.' });
  }
};

// 5. ROTAS ADMINISTRATIVAS
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, name, phone, role, subscription_status, created_at');

    if (error) throw error;
    return res.json(users);
  } catch (err) {
    return res.status(500).json({ error: 'Erro ao buscar usuários: ' + err.message });
  }
});

app.put('/admin/users/:id/status', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const { error } = await supabase.from('users').update({ subscription_status: status }).eq('id', id);
    if (error) throw error;
    return res.json({ message: 'Status atualizado com sucesso!' });
  } catch (err) {
    return res.status(500).json({ error: 'Erro ao atualizar status: ' + err.message });
  }
});

app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const { error } = await supabase.from('users').delete().eq('id', id);
    if (error) throw error;
    return res.json({ message: 'Usuário removido com sucesso!' });
  } catch (err) {
    return res.status(500).json({ error: 'Erro ao deletar usuário: ' + err.message });
  }
});

// 6. ROTAS DO JOGO, RANKING E POTE DE OURO

// Buscar Pote de Ouro (R$ 5/ativo) e Top 10 Ranking
app.get('/game/leaderboard', async (req, res) => {
  try {
    const { count: activeUsers, error: countError } = await supabase
      .from('users')
      .select('id', { count: 'exact', head: true })
      .eq('subscription_status', 'ACTIVE');

    if (countError) throw countError;

    const poteDeOuro = (activeUsers || 0) * 5;

    const { data: topUsers, error: rankError } = await supabase
      .from('users')
      .select('name, phone, high_score')
      .gt('high_score', 0)
      .order('high_score', { ascending: false })
      .limit(10);

    if (rankError) throw rankError;

    return res.json({
      poteDeOuro,
      ranking: topUsers.map((user, index) => ({
        posicao: index + 1,
        nome: user.name || `Jogador ***${user.phone ? user.phone.slice(-4) : '0000'}`,
        pontos: user.high_score
      }))
    });
  } catch (err) {
    return res.status(500).json({ error: 'Erro ao carregar ranking: ' + err.message });
  }
});

// Salvar/Atualizar Pontuação do Jogador
app.post('/game/score', requireActiveSubscription, async (req, res) => {
  const { score } = req.body;
  const user = req.user;

  if (typeof score !== 'number') {
    return res.status(400).json({ error: 'Pontuação inválida.' });
  }

  try {
    // Atualiza apenas se a nova pontuação for maior que o recorde atual do usuário
    if (score > (user.high_score || 0)) {
      const { error } = await supabase
        .from('users')
        .update({ high_score: score })
        .eq('id', user.id);

      if (error) throw error;

      return res.json({ message: 'Novo recorde registrado com sucesso!', newRecord: true, score });
    }

    return res.json({ message: 'Pontuação computada (não superou seu recorde).', newRecord: false, score: user.high_score });
  } catch (err) {
    return res.status(500).json({ error: 'Erro ao salvar pontuação: ' + err.message });
  }
});

// Rota de Acesso Liberado ao Jogo
app.get('/game/play', requireActiveSubscription, (req, res) => {
  return res.json({
    message: 'Acesso liberado!',
    gameUrl: '/game.html',
  });
});

// Inicialização do Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
