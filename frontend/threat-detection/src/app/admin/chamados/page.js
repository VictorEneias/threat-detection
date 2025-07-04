'use client';
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getCookie } from 'cookies-next';

function ChamadoCard({ chamado, onDelete }) {
  const [open, setOpen] = useState(false);
  const [details, setDetails] = useState(null);

  const toggle = async () => {
    if (!open && !details) {
      const res = await fetch(`/api/chamados/${chamado.id}`, {
        headers: { Authorization: `Bearer ${getCookie('adminToken')}` },
      });
      if (res.ok) {
        const data = await res.json();
        setDetails(data);
      }
    }
    setOpen(!open);
  };
  const r = details ? details.relatorio : {};
  return (
    <div className="bg-[#1a1a1a] p-4 rounded border-l-4 border-[#ec008c]">
      <div className="flex justify-between items-start">
        <div>
          <h2 className="font-semibold">{chamado.nome} - {chamado.empresa}</h2>
          <p className="text-xs text-gray-400">{new Date(chamado.timestamp + 'Z').toLocaleString()}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={toggle} className="bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded">
            {open ? 'Fechar' : 'Ler mais'}
          </button>
          <button
            onClick={() => onDelete(chamado.id)}
            className="bg-red-600 hover:bg-red-500 text-white px-2 py-1 rounded"
          >
            Excluir
          </button>
        </div>
      </div>
      {open && details && (
        <div className="mt-2 text-sm space-y-1">
          <p>Cargo: {details.cargo}</p>
          <p>Telefone: {details.telefone}</p>
          <p>Mensagem: {details.mensagem}</p>
          <div className="mt-2">
            <p className="font-semibold">Relatório:</p>
            <p>Domínio: {r.dominio}</p>
            <p>Subdomínios: {r.num_subdominios}</p>
            <p>IPs únicos: {r.num_ips}</p>
            <p>Score Portas: {Math.round(r.port_score * 100)}</p>
            <p>Score Softwares: {Math.round(r.software_score * 100)}</p>
            <p>Score Vazamentos: {Math.round(r.leak_score * 100)}</p>
            <p>Emails Vazados: {r.num_emails ?? 0}</p>
            <p>Senhas Vazadas: {r.num_passwords ?? 0}</p>
            <p>Hashes Vazadas: {r.num_hashes ?? 0}</p>
            <p>Score Final: {Math.round(r.final_score * 100)}</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ChamadosPage() {
  const [chamados, setChamados] = useState([]);
  const router = useRouter();

  useEffect(() => {
    const fetchChamados = async () => {
      const res = await fetch('/api/chamados/summary', {
        headers: { Authorization: `Bearer ${getCookie('adminToken')}` },
      });
      const data = await res.json();
      data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      setChamados(data);
    };
    fetchChamados();
  }, []);

  const handleDelete = async (id) => {
    if (!confirm('Excluir chamado?')) return;
    const res = await fetch(`/api/chamados/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${getCookie('adminToken')}` },
    });
    if (res.ok) {
      setChamados((prev) => prev.filter((c) => c.id !== id));
    } else {
      alert('Falha ao excluir chamado');
    }
  };

  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white p-4 gap-4">
      <h1 className="text-2xl font-bold">Chamados</h1>
      <button onClick={() => router.push('/admin')} className="bg-gray-700 px-3 py-1 rounded hover:bg-gray-600">
        Voltar
      </button>
      <div className="w-full max-w-3xl flex flex-col gap-4">
        {chamados.length === 0 && <p className="text-center">Nenhum chamado.</p>}
        {chamados.map((c) => (
          <ChamadoCard key={c.id} chamado={c} onDelete={handleDelete} />
        ))}
      </div>
    </main>
  );
}