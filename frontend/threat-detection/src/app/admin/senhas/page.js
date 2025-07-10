'use client';
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getCookie } from 'cookies-next';

export default function SenhasPage() {
  const [senhas, setSenhas] = useState([]);
  const [ultima, setUltima] = useState('');
  const router = useRouter();

  const fetchSenhas = async () => {
    const res = await fetch('/api/temp-passwords', {
      headers: { Authorization: `Bearer ${getCookie('userToken')}` },
    });
    if (res.ok) {
      const data = await res.json();
      data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      setSenhas(data);
    }
  };

  useEffect(() => {
    fetchSenhas();
  }, []);

  const gerarSenha = async () => {
    const res = await fetch('/api/temp-passwords', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${getCookie('userToken')}`,
      },
      body: JSON.stringify({}),
    });
    if (res.ok) {
      const data = await res.json();
      setUltima(data.password);
      fetchSenhas();
    }
  };

  const copiar = () => {
    navigator.clipboard.writeText(ultima);
    alert('Copiada!');
  };

  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white p-4 gap-4">
      <h1 className="text-2xl font-bold">Senhas Temporárias</h1>
      <button onClick={() => router.push('/admin')} className="bg-gray-700 px-3 py-1 rounded hover:bg-gray-600">Voltar</button>
      <div className="flex flex-col items-center gap-2">
        <button onClick={gerarSenha} className="bg-green-600 px-4 py-2 rounded hover:bg-green-500">Gerar Senha</button>
        {ultima && (
          <div className="flex items-center gap-2">
            <span className="font-mono bg-[#1a1a1a] px-2 py-1 rounded border border-gray-700">{ultima}</span>
            <button onClick={copiar} className="bg-gray-700 px-2 py-1 rounded hover:bg-gray-600">Copiar</button>
          </div>
        )}
      </div>
      <div className="w-full max-w-md flex flex-col gap-2 mt-4">
        {senhas.map((s) => (
          <div key={s.id} className="bg-[#1a1a1a] p-3 rounded border-l-4 border-[#ec008c] text-sm flex justify-between">
            <span>{new Date(s.timestamp + 'Z').toLocaleString()}</span>
            <span>{s.used ? 'Usada' : 'Ativa'}</span>
          </div>
        ))}
      </div>
    </main>
  );
}
