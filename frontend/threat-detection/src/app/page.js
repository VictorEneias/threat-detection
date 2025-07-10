'use client';
import { useState, useEffect } from 'react';
import { getCookie, setCookie, deleteCookie } from 'cookies-next';
import EmailForm from './EmailForm';

export default function Home() {
  const [logged, setLogged] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');
  const [regUser, setRegUser] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPass, setRegPass] = useState('');
  const [regPass2, setRegPass2] = useState('');
  const [showRegister, setShowRegister] = useState(false);
  const [autenticado, setAutenticado] = useState(false);
  const [senha, setSenha] = useState('');

  useEffect(() => {
    const t = getCookie('userToken');
    const adm = getCookie('isAdmin');
    if (t) {
      setLogged(true);
      setIsAdmin(adm === 'true');
    }
  }, []);

  const doLogin = async (e) => {
    e.preventDefault();
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: loginUser, password: loginPass }),
    });
    if (res.ok) {
      const data = await res.json();
      setCookie('userToken', data.token, { maxAge: 60 * 60 * 24 * 30 });
      setCookie('isAdmin', data.is_admin ? 'true' : 'false', { maxAge: 60 * 60 * 24 * 30 });
      setLogged(true);
      setIsAdmin(data.is_admin);
    } else {
      alert('Falha no login');
    }
  };

  const doRegister = async (e) => {
    e.preventDefault();
    if (regPass !== regPass2) {
      alert('Senhas diferentes');
      return;
    }
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: regUser, email: regEmail, password: regPass }),
    });
    if (res.ok) {
      alert('Registro realizado, faça login.');
      setShowRegister(false);
    } else {
      const err = await res.json();
      alert(err.detail || 'Erro no registro');
    }
  };

  const logout = () => {
    deleteCookie('userToken', { path: '/' });
    deleteCookie('isAdmin', { path: '/' });
    setLogged(false);
    setIsAdmin(false);
    setAutenticado(false);
  };

  if (!logged) {
    if (showRegister) {
      return (
        <main className="min-h-screen flex items-center justify-center bg-black text-white">
          <form onSubmit={doRegister} className="bg-[#1a1a1a] p-6 rounded flex flex-col gap-2 w-80 text-white border border-[#ec008c]">
            <h2 className="text-center text-xl font-bold mb-2">Registrar</h2>
            <input type="text" placeholder="Usuário" value={regUser} onChange={(e) => setRegUser(e.target.value)} className="p-2 rounded text-white" required />
            <input type="email" placeholder="Email" value={regEmail} onChange={(e) => setRegEmail(e.target.value)} className="p-2 rounded text-white" required />
            <input type="password" placeholder="Senha" value={regPass} onChange={(e) => setRegPass(e.target.value)} className="p-2 rounded text-white" required />
            <input type="password" placeholder="Confirme" value={regPass2} onChange={(e) => setRegPass2(e.target.value)} className="p-2 rounded text-white" required />
            <button type="submit" className="bg-[#ec008c] hover:bg-pink-600 text-white px-4 py-2 rounded font-semibold">Registrar</button>
            <button type="button" onClick={() => setShowRegister(false)} className="text-sm mt-1">Voltar</button>
          </form>
        </main>
      );
    }
    return (
      <main className="min-h-screen flex items-center justify-center bg-black text-white">
        <form onSubmit={doLogin} className="bg-[#1a1a1a] p-6 rounded flex flex-col gap-2 w-80 text-white border border-[#ec008c]">
          <h2 className="text-center text-xl font-bold mb-2">Login</h2>
          <input type="text" placeholder="Usuário" value={loginUser} onChange={(e) => setLoginUser(e.target.value)} className="p-2 rounded text-white" required />
          <input type="password" placeholder="Senha" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} className="p-2 rounded text-white" required />
          <button type="submit" className="bg-[#ec008c] hover:bg-pink-600 text-white px-4 py-2 rounded font-semibold">Entrar</button>
          <button type="button" onClick={() => setShowRegister(true)} className="text-sm mt-1">Criar conta</button>
        </form>
      </main>
    );
  }

  if (!isAdmin && !autenticado) {
    const handleSubmit = async (e) => {
      e.preventDefault();
      const res = await fetch('/api/check-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: senha }),
      });
      if (res.ok) {
        setAutenticado(true);
      } else {
        alert('Senha incorreta');
      }
    };
    return (
      <main className="min-h-screen flex items-center justify-center bg-black text-white">
        <form onSubmit={handleSubmit} className="bg-[#1a1a1a] p-4 rounded shadow-lg flex flex-col md:flex-row gap-2 text-white border border-[#ec008c]">
          <input type="password" placeholder="Senha" value={senha} onChange={(e) => setSenha(e.target.value)} className="p-2 rounded text-black outline-none bg-white" required />
          <button type="submit" className="bg-[#ec008c] hover:bg-pink-600 text-white px-4 py-2 rounded font-semibold">Entrar</button>
        </form>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex flex-col items-center text-white gap-2 bg-fixed bg-cover bg-center bg-no-repeat" style={{ backgroundImage: "url('/BGSITE.png')" }}>
      <header className="w-full bg-white py-4 px-6 flex items-center justify-between shadow-md">
        <div className="flex items-center gap-3">
          <img src="/crLogoNG.png" alt="Logo NGSX" className="w-32 md:w-40 object-contain" />
        </div>
        <button onClick={logout} className="text-black text-sm">Sair</button>
      </header>
      <div className="flex-1 flex items-center justify-center w-full px-4">
        <EmailForm />
      </div>
    </main>
  );
}
