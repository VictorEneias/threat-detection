'use client';
import { useEffect, useState } from 'react';

export default function Relatorios() {
  const [lista, setLista] = useState([]);
  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    fetch('/api/admin/reports', { headers: { 'X-Admin-Token': token } })
      .then(r => r.json())
      .then(setLista);
  }, []);

  return (
    <main className="min-h-screen bg-black text-white p-4">
      <h1 className="text-2xl mb-4">Relatórios</h1>
      <ul className="space-y-2">
        {lista.map((r) => (
          <li key={r.job_id} className="border p-2 rounded">
            <span className="mr-2">{r.dominio}</span>
            <a className="text-pink-400 underline" href={`/api/admin/report/${r.job_id}`} target="_blank">baixar</a>
          </li>
        ))}
      </ul>
    </main>
  );
}
