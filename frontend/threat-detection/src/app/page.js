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
        <form onSubmit={handleSubmit} className="bg-[#1a1a1a] p-4 rounded shadow-lg flex flex-col md:flex-row gap-2 text-white border border-[#ec008c]">
          <input
            type="password"
            placeholder="Senha"
            value={senha}
            onChange={(e) => setSenha(e.target.value)}
            className="p-2 rounded text-black outline-none bg-white"
            required
          />
          <button type="submit" className="bg-[#ec008c] hover:bg-pink-600 text-white px-4 py-2 rounded font-semibold">
            Entrar
          </button>
        </form>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white gap-2">
      <header className="w-full bg-[#ec008c] py-4 text-center">
        <h1 className="font-bold text-lg md:text-2xl uppercase">ANÁLISE DE SEGURANÇA CORPORATIVA</h1>
      </header>
      <div className="flex-1 flex items-center justify-center w-full px-4">
        <EmailForm />
      </div>
      <div className="fixed bottom-4 right-4 flex flex-col items-end gap-3 z-50">
        <a
          href="https://ngsx.com.br"
          target="_blank"
          className="min-w-[160px] text-center bg-[#ec008c] hover:bg-pink-700 text-white px-4 py-2 rounded-full shadow-lg font-medium text-sm flex items-center justify-center gap-2">
          <img src="/favicon.ico" alt="NGSXIcon" className="w-5 h-5" />
          Site NGSX
        </a>
        <a
          href="https://api.whatsapp.com/send?phone=556130341227"
          target="_blank"
          className="min-w-[160px] text-center bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-full shadow-lg font-medium text-sm flex items-center justify-center gap-1">
          <img src="/whatsapp.png" alt="WhatsApp" className="w-5 h-5" />
          WhatsApp
        </a>
      </div>
    </main>
  );
}