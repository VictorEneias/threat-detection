'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

function ReportCard({ dominio, info, onDelete }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="bg-[#1a1a1a] p-4 rounded border-l-4 border-[#ec008c]">
      <div className="flex justify-between items-center">
        <h2 className="font-semibold">{dominio}</h2>
        <div className="flex gap-2">
          <button onClick={() => setOpen(!open)} className="underline">
            {open ? 'Fechar' : 'Ler mais'}
          </button>
          <button
            onClick={() => onDelete(dominio)}
            className="text-red-500 underline"
          >
            Excluir
          </button>
        </div>
      </div>
      {open && (
        <div className="mt-2 text-sm">
          <p>Subdomínios: {info.num_subdominios}</p>
          <p>IPs únicos: {info.num_ips}</p>
          <p>Nota Portas: {info.port_score}</p>
          <p>Nota Softwares: {info.software_score}</p>
          <p>Nota Final: {info.final_score}</p>
          <div className="mt-2">
            <p className="font-semibold">Alertas de Portas:</p>
            {info.port_alertas && info.port_alertas.length > 0 ? (
              <ul className="list-disc list-inside">
                {info.port_alertas.map((a, i) => (
                  <li key={i}>
                    <strong>{a.ip}:{a.porta}</strong> → {a.mensagem}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-gray-400 text-xs">Nenhum alerta.</p>
            )}
          </div>
          <div className="mt-2">
            <p className="font-semibold">Alertas de Softwares:</p>
            {info.software_alertas && info.software_alertas.length > 0 ? (
              <ul className="list-disc list-inside">
                {info.software_alertas.map((a, i) => (
                  <li key={i}>
                    <strong>{a.ip}:{a.porta}</strong> → {a.software} vulnerável a {a.cve_id} (CVSS {a.cvss})
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-gray-400 text-xs">Nenhum alerta.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function RelatoriosPage() {
  const [reports, setReports] = useState({});
  const router = useRouter();

  const handleDelete = async (dom) => {
    if (!confirm(`Excluir relatorio de ${dom}?`)) return;
    const res = await fetch(`/api/reports/${dom}`, { method: 'DELETE' });
    if (res.ok) {
      setReports((prev) => {
        const copy = { ...prev };
        delete copy[dom];
        return copy;
      });
    } else {
      alert('Falha ao excluir relatório');
    }
  };

  useEffect(() => {
    const fetchReports = async () => {
      const res = await fetch('/api/reports');
      const data = await res.json();
      setReports(data);
    };
    fetchReports();
  }, []);

  const keys = Object.keys(reports);

  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white p-4 gap-4">
      <h1 className="text-2xl font-bold">Relatórios</h1>
      <button onClick={() => router.push('/admin')} className="bg-gray-700 px-3 py-1 rounded">
        Voltar
      </button>
      <div className="w-full max-w-3xl flex flex-col gap-4">
        {keys.length === 0 && <p className="text-center">Nenhum relatório disponível.</p>}
        {keys.map((dom) => (
          <ReportCard
            key={dom}
            dominio={dom}
            info={reports[dom]}
            onDelete={handleDelete}
          />
        ))}
      </div>
    </main>
  );
}