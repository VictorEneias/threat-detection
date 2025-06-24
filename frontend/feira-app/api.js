const API_BASE = 'http://localhost:8000';
let token = localStorage.getItem('token');

function setToken(t) {
  token = t;
  if (t) {
    localStorage.setItem('token', t);
  } else {
    localStorage.removeItem('token');
  }
}

function headers(auth = false) {
  const h = { 'Content-Type': 'application/json' };
  if (auth && token) h['Authorization'] = `Bearer ${token}`;
  return h;
}

async function loginApi(email, senha) {
  const res = await fetch(`${API_BASE}/login`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ email, senha })
  });
  if (!res.ok) throw new Error('Falha no login');
  const data = await res.json();
  setToken(data.access_token);
  return data;
}

async function getFeiras() {
  const res = await fetch(`${API_BASE}/feiras`, { headers: headers() });
  if (!res.ok) throw new Error('Erro ao buscar feiras');
  return await res.json();
}

async function criarFeira(nome) {
  const res = await fetch(`${API_BASE}/feiras`, {
    method: 'POST',
    headers: headers(true),
    body: JSON.stringify({ nome })
  });
  if (!res.ok) throw new Error('Erro ao criar feira');
  return await res.json();
}

async function deletarFeira(id) {
  const res = await fetch(`${API_BASE}/feiras/${id}`, {
    method: 'DELETE',
    headers: headers(true)
  });
  if (!res.ok) throw new Error('Erro ao remover');
  return await res.json();
}
