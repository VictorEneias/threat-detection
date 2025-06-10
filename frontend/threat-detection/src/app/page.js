'use client';
import { useState } from 'react';
import EmailForm from './EmailForm';

const APP_PASS = process.env.NEXT_PUBLIC_APP_PASSWORD || 'senha';

export default function Home() {
  const [autenticado, setAutenticado] = useState(false);
  const [senha, setSenha] = useState('');

  if (!autenticado) {
    const handleSubmit = (e) => {
      e.preventDefault();
      if (senha === APP_PASS) {
        setAutenticado(true);
      } else {
        alert('Senha incorreta');
      }
    };

    return (
      <main className="min-h-screen flex items-center justify-center bg-black text-white">
        <form onSubmit={handleSubmit} className="bg-[#ec008c] p-4 rounded flex gap-2">
          <input
            type="password"
            placeholder="Senha"
            value={senha}
            onChange={(e) => setSenha(e.target.value)}
            className="p-2 rounded text-black"
            required
          />
          <button type="submit" className="bg-black text-white px-4 py-2 rounded">
            Entrar
          </button>
        </form>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white">
      <header className="w-full bg-[#ec008c] py-4 text-center">
        <h1 className="font-bold text-lg md:text-2xl uppercase">ANÁLISE DE SEGURANÇA CORPORATIVA</h1>
      </header>
      <div className="flex-1 flex items-center justify-center w-full px-4">
        <EmailForm />
      </div>
    </main>
  );
}