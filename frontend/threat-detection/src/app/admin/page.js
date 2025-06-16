'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function AdminLogin() {
  const [senha, setSenha] = useState('');
  const router = useRouter();

  const handle = (e) => {
    e.preventDefault();
    if (!senha) return;
    localStorage.setItem('admin_token', senha);
    router.push('/admin/relatorios');
  };

  return (
    <main className="min-h-screen flex items-center justify-center bg-black text-white">
      <form onSubmit={handle} className="bg-[#1a1a1a] p-4 rounded flex gap-2">
        <input type="password" className="p-2 rounded text-black" placeholder="Senha" value={senha} onChange={(e)=>setSenha(e.target.value)} required />
        <button className="bg-pink-700 text-white px-4 py-2 rounded" type="submit">Entrar</button>
      </form>
    </main>
  );
}
