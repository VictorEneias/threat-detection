'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

function ReportCard({ dominio, timestamp, onDelete }) {
  const [open, setOpen] = useState(false);
  const [info, setInfo] = useState(null);

  const toggle = async () => {
    if (!open && !info) {
      const res = await fetch(`/api/reports/${dominio}`);
      if (res.ok) {
        const data = await res.json();
        setInfo(data);
      }
    }
    setOpen(!open);
  };

  const exportar = async () => {
    const res = await fetch(`/api/reports/${dominio}/pdf`);
    if (res.ok) {
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${dominio}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } else {
      alert('Falha ao gerar PDF');
    }
  };
  return (
    <div className="bg-[#1a1a1a] p-4 rounded border-l-4 border-[#ec008c]">
      <div className="flex justify-between items-start">
        <div>
          <h2 className="font-semibold">{dominio}</h2>
          <p className="text-xs text-gray-400">{new Date(timestamp + 'Z').toLocaleString()}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={toggle} className="bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded">
            {open ? 'Fechar' : 'Ler mais'}
          </button>
          <button onClick={exportar} className="bg-blue-600 hover:bg-blue-500 text-white px-2 py-1 rounded">
            Exportar PDF
          </button>
          <button
            onClick={() => onDelete(dominio)}
            className="bg-red-600 hover:bg-red-500 text-white px-2 py-1 rounded"
          >
            Excluir
          </button>
        </div>
      </div>
      {open && info && (
        <div className="mt-2 text-sm">
          <p>Subdomínios: {info.num_subdominios}</p>
          <p>IPs únicos: {info.num_ips}</p>
          <p>Nota Portas: {Math.round(info.port_score * 100)}</p>
          <p>Nota Softwares: {Math.round(info.software_score * 100)}</p>
          <p>Nota Vazamentos: {Math.round(info.leak_score * 100)}</p>
          <p>Emails Vazados: {info.num_emails ?? 0}</p>
          <p>Senhas Vazadas: {info.num_passwords ?? 0}</p>
          <p>Hashes Vazados: {info.num_hashes ?? 0}</p>
          <p>Nota Final: {Math.round(info.final_score * 100)}</p>
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
          {info.leaked_data && info.leaked_data.length > 0 && (
            <div className="mt-2">
              <p className="font-semibold mb-1">Dados Vazados:</p>
              <table className="w-full table-fixed text-xs border-collapse">
                <thead>
                  <tr>
                    <th className="border px-2 w-1/4">Email</th>
                    <th className="border px-2 w-1/4">Senha texto</th>
                    <th className="border px-2 w-2/4">Senha hash</th>
                  </tr>
                </thead>
                <tbody>
                  {info.leaked_data.map((row, idx) => (
                    <tr key={idx}>
                      <td className="border px-2 w-2/8 break-all">{row.email}</td>
                      <td className="border px-2 w-1/8 break-all">{row.password}</td>
                      <td className="border px-2 w-5/8 break-all">{row.hash}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function RelatoriosPage() {
  const [reports, setReports] = useState([]);
  const router = useRouter();

  const handleDelete = async (dom) => {
    if (!confirm(`Excluir relatorio de ${dom}?`)) return;
    const res = await fetch(`/api/reports/${dom}`, { method: 'DELETE' });
    if (res.ok) {
      setReports((prev) => prev.filter((d) => d.dominio !== dom));
    } else {
      alert('Falha ao excluir relatório');
    }
  };

  useEffect(() => {
    const fetchReports = async () => {
      const res = await fetch('/api/reports/summary');
      const data = await res.json();
      data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      setReports(data);
    };
    fetchReports();
  }, []);


  return (
    <main className="min-h-screen flex flex-col items-center bg-black text-white p-4 gap-4">
      <h1 className="text-2xl font-bold">Relatórios</h1>
      <button onClick={() => router.push('/admin')} className="bg-gray-700 px-3 py-1 rounded hover:bg-gray-600">
        Voltar
      </button>
      <div className="w-full max-w-5xl flex flex-col gap-4">
        {reports.length === 0 && <p className="text-center">Nenhum relatório disponível.</p>}
        {reports.map((r) => (
          <ReportCard key={r.dominio} dominio={r.dominio} timestamp={r.timestamp} onDelete={handleDelete} />
        ))}
      </div>
    </main>
  );
}