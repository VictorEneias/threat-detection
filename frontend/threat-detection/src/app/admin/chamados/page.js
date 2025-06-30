'use client';
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

function ChamadoCard({ chamado, onDelete }) {
  const [open, setOpen] = useState(false);
  const [details, setDetails] = useState(null);

  const toggle = async () => {
    if (!open && !details) {
      const res = await fetch(`/api/chamados/${chamado.id}`);
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
      <div className="flex justify-between items-center">
        <h2 className="font-semibold">{chamado.nome} - {chamado.empresa}</h2>
        <div className="flex gap-2">
          <button onClick={toggle} className="underline">
            {open ? 'Fechar' : 'Ler mais'}
          </button>
          <button
            onClick={() => onDelete(chamado.id)}
            className="text-red-500 underline"
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
      const res = await fetch('/api/chamados/summary');
      const data = await res.json();
      setChamados(data);
    };
    fetchChamados();
  }, []);

  const handleDelete = async (id) => {
    if (!confirm('Excluir chamado?')) return;
    const res = await fetch(`/api/chamados/${id}`, { method: 'DELETE' });
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