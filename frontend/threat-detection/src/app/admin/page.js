'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getCookie, setCookie, deleteCookie } from 'cookies-next';

export default function AdminPage() {
  const router = useRouter();
  const [loggedIn, setLoggedIn] = useState(false);
  const [user, setUser] = useState('');
  const [pass, setPass] = useState('');
  const [lembrar, setLembrar] = useState(false);

  useEffect(() => {
    const token = getCookie('userToken');
    const adminFlag = getCookie('isAdmin');
    if (token && adminFlag === 'true') {
      setLoggedIn(true);
    }
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass }),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.is_admin) {
        if (lembrar) {
          const opts = { maxAge: 60 * 60 * 24 * 30 };
          setCookie('userToken', data.token, opts);
          setCookie('isAdmin', 'true', opts);
        } else {
          setCookie('userToken', data.token);
          setCookie('isAdmin', 'true');
        }
        setLoggedIn(true);
      } else {
        alert('Não é administrador');
      }
    } else {
      alert('Credenciais inválidas');
    }
  };

  const handleLogout = () => {
    deleteCookie('userToken', { path: '/' });
    deleteCookie('isAdmin', { path: '/' });
    setLoggedIn(false);             // <- atualiza o estado
    setUser('');         // <-- limpa o campo usuário
    setPass(''); 
    router.replace('/admin');       // <- volta pra tela de login
  };

  if (loggedIn) {
    return (
      <main className="min-h-screen flex flex-col items-center justify-center gap-4 bg-black text-white">
        <h1 className="text-2xl font-bold">Painel do Administrador</h1>
        <div className="flex gap-4">
          <button
            onClick={() => router.push('/admin/relatorios')}
            className="bg-gray-700 px-4 py-2 rounded hover:bg-gray-600"
          >
            Relatórios
          </button>
          <button
            onClick={() => router.push('/admin/chamados')}
            className="bg-gray-700 px-4 py-2 rounded hover:bg-gray-600"
          >
            Chamados
          </button>
          <button
            onClick={() => router.push('/admin/senhas')}
            className="bg-gray-700 px-4 py-2 rounded hover:bg-gray-600"
          >
            Senhas
          </button>
          <button
            onClick={() => router.push('/admin/usuarios')}
            className="bg-gray-700 px-4 py-2 rounded hover:bg-gray-600"
          >
            Usuários
          </button>
          <button
            onClick={handleLogout}
            className="bg-pink-600 px-4 py-2 rounded hover:bg-pink-500"
          >
            Sair
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex items-center justify-center bg-black text-white">
      <form onSubmit={handleLogin} className="bg-[#1a1a1a] p-6 rounded flex flex-col gap-2 w-80 text-white border border-[#ec008c]">
        <h2 className="text-center text-xl font-bold mb-2">Login Admin</h2>
        <input
          type="text"
          placeholder="Usuário"
          value={user}
          onChange={(e) => setUser(e.target.value)}
          className="p-2 rounded text-black outline-none bg-white"
          required
        />
        <input
          type="password"
          placeholder="Senha"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          className="p-2 rounded text-black outline-none bg-white"
          required
        />
        <label className="text-sm flex items-center gap-2">
          <input
            type="checkbox"
            checked={lembrar}
            onChange={(e) => setLembrar(e.target.checked)}
          />
          Permanecer logado por 30 dias
        </label>
        <button type="submit" className="bg-[#ec008c] hover:bg-pink-600 text-white px-4 py-2 rounded font-semibold">
          Entrar
        </button>
      </form>
    </main>
  );
}
