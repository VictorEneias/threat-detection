'use client';
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

function ChamadoCard({ chamado }) {
  const [open, setOpen] = useState(false);
  const r = chamado.relatorio || {};
  return (
    <div className="bg-[#1a1a1a] p-4 rounded border-l-4 border-[#ec008c]">
      <div className="flex justify-between items-center">
        <h2 className="font-semibold">{chamado.nome} - {chamado.empresa}</h2>
        <button onClick={() => setOpen(!open)} className="underline">
          {open ? 'Fechar' : 'Ler mais'}
        </button>
      </div>
      {open && (
        <div className="mt-2 text-sm space-y-1">
          <p>Cargo: {chamado.cargo}</p>
          <p>Telefone: {chamado.telefone}</p>
          <p>Mensagem: {chamado.mensagem}</p>
          <div className="mt-2">
            <p className="font-semibold">Relatório:</p>
            <p>Domínio: {r.dominio}</p>
            <p>Subdomínios: {r.num_subdominios}</p>
            <p>IPs únicos: {r.num_ips}</p>
            <p>Score Portas: {r.port_score}</p>
            <p>Score Softwares: {r.software_score}</p>
            <p>Score Final: {r.final_score}</p>
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
      const res = await fetch('/api/chamados');
      const data = await res.json();
      setChamados(data);
    };
    fetchChamados();
  }, []);

  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white p-4 gap-4">
      <h1 className="text-2xl font-bold">Chamados</h1>
      <button onClick={() => router.push('/admin')} className="bg-gray-700 px-3 py-1 rounded">
        Voltar
      </button>
      <div className="w-full max-w-3xl flex flex-col gap-4">
        {chamados.length === 0 && <p className="text-center">Nenhum chamado.</p>}
        {chamados.map((c) => (
          <ChamadoCard key={c.id} chamado={c} />
        ))}
      </div>
    </main>
  );
}