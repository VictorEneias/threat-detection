'use client';
import { useEffect, useState } from 'react';

export default function Chamados() {
  const [lista, setLista] = useState([]);
  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    fetch('/api/admin/tickets', { headers: { 'X-Admin-Token': token } })
      .then(r => r.json())
      .then(setLista);
  }, []);

  return (
    <main className="min-h-screen bg-black text-white p-4">
      <h1 className="text-2xl mb-4">Chamados</h1>
      <ul className="space-y-4">
        {lista.map((c) => (
          <li key={c.id} className="border p-2 rounded">
            <p><strong>{c.nome}</strong> ({c.empresa})</p>
            <p>{c.cargo} - {c.telefone}</p>
            <p>{c.mensagem}</p>
          </li>
        ))}
      </ul>
    </main>
  );
}
