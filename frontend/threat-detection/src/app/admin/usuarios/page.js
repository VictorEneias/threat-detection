'use client';
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getCookie } from 'cookies-next';

export default function UsuariosPage() {
  const [users, setUsers] = useState([]);
  const router = useRouter();

  const fetchUsers = async () => {
    const res = await fetch('/api/users', {
      headers: { Authorization: `Bearer ${getCookie('userToken')}` },
    });
    if (res.ok) {
      const data = await res.json();
      setUsers(data);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const setAdmin = async (id, val) => {
    await fetch(`/api/users/${id}/admin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${getCookie('userToken')}`,
      },
      body: JSON.stringify({ is_admin: val }),
    });
    fetchUsers();
  };

  const remove = async (id) => {
    if (!confirm('Excluir usuario?')) return;
    await fetch(`/api/users/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${getCookie('userToken')}` },
    });
    fetchUsers();
  };

  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white p-4 gap-4">
      <h1 className="text-2xl font-bold">Usuários</h1>
      <button onClick={() => router.push('/admin')} className="bg-gray-700 px-3 py-1 rounded hover:bg-gray-600">Voltar</button>
      <div className="w-full max-w-md flex flex-col gap-2 mt-4">
        {users.map(u => (
          <div key={u.id} className="bg-[#1a1a1a] p-3 rounded border-l-4 border-[#ec008c] flex justify-between items-center">
            <div>
              <p className="font-semibold">{u.username}</p>
              <p className="text-xs text-gray-400">{u.email}</p>
            </div>
            <div className="flex gap-2 text-sm">
              <button onClick={() => setAdmin(u.id, !u.is_admin)} className="bg-blue-600 px-2 py-1 rounded">
                {u.is_admin ? 'Revogar' : 'Tornar'} Admin
              </button>
              <button onClick={() => remove(u.id)} className="bg-red-600 px-2 py-1 rounded">Excluir</button>
            </div>
          </div>
        ))}
      </div>
    </main>
  );
}
