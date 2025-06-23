'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getCookie, setCookie, deleteCookie } from 'cookies-next';

// Simulação de "banco de usuários" (admin)
const USERS = [
  { username: 'admin', password: '1234' },
  { username: 'root', password: 'senhaSegura' },
];

export default function AdminPage() {
  const router = useRouter();
  const [loggedIn, setLoggedIn] = useState(false);
  const [user, setUser] = useState('');
  const [pass, setPass] = useState('');

  useEffect(() => {
    const isAdmin = getCookie('isAdmin');
    if (isAdmin === 'true') {
      setLoggedIn(true);
    }
  }, []);

  const handleLogin = (e) => {
    e.preventDefault();
    const found = USERS.find(
      (u) => u.username === user && u.password === pass
    );
    if (found) {
      setCookie('isAdmin', 'true');
      setLoggedIn(true);
    } else {
      alert('Credenciais inválidas');
    }
  };

  const handleLogout = () => {
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
      <form onSubmit={handleLogin} className="bg-[#ec008c] p-6 rounded flex flex-col gap-2 w-80">
        <h2 className="text-center text-xl font-bold mb-2">Login Admin</h2>
        <input
          type="text"
          placeholder="Usuário"
          value={user}
          onChange={(e) => setUser(e.target.value)}
          className="p-2 rounded text-black"
          required
        />
        <input
          type="password"
          placeholder="Senha"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          className="p-2 rounded text-black"
          required
        />
        <button type="submit" className="bg-black text-white px-4 py-2 rounded mt-2">
          Entrar
        </button>
      </form>
    </main>
  );
}
