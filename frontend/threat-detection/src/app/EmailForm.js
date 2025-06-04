'use client';
import { useState } from 'react';

export default function EmailForm() {
  const [email, setEmail] = useState('');
  const [loadingPort, setLoadingPort] = useState(false);
  const [loadingSoft, setLoadingSoft] = useState(false);
  const [jobId, setJobId] = useState(null);
  const [portAlerts, setPortAlerts] = useState([]);
  const [softAlerts, setSoftAlerts] = useState([]);
  const [showPort, setShowPort] = useState(false);
  const [showSoft, setShowSoft] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoadingPort(true);
    setLoadingSoft(true);
    setPortAlerts([]);
    setSoftAlerts([]);

    try {
      const res = await fetch('http://localhost:8000/api/port-analysis', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });

      const data = await res.json();
      if (data.erro) {
        alert(`Erro: ${data.erro}`);
        setLoadingPort(false);
        setLoadingSoft(false);
        return;
      }
      setJobId(data.job_id);
      setPortAlerts(data.alertas || []);
      setLoadingPort(false);
      pollSoftware(data.job_id);
    } catch (err) {
      alert('Erro ao conectar ao backend');
      setLoadingPort(false);
      setLoadingSoft(false);
    }
  };

  const pollSoftware = async (id) => {
    if (!id) return;
    try {
      const res = await fetch(`http://localhost:8000/api/software-analysis/${id}`);
      const data = await res.json();
      if (data.alertas) {
        setSoftAlerts(data.alertas);
        setLoadingSoft(false);
      } else {
        setTimeout(() => pollSoftware(id), 2000);
      }
    } catch (e) {
      setTimeout(() => pollSoftware(id), 2000);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="bg-[#ec008c] p-4 rounded-md space-y-4 text-black w-full max-w-md">
        <input
          type="email"
          placeholder="contato@empresa.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="p-2 w-full rounded text-black placeholder-gray-700"
          required
        />
        <button
          type="submit"
          className="bg-black text-white px-4 py-2 rounded w-full"
          disabled={loadingPort || loadingSoft}
        >
          {loadingPort ? 'Analisando...' : 'Analisar'}
        </button>
      </div>

      <div className="space-y-4 pt-4 w-full max-w-2xl">
        <div className="bg-[#ec008c] text-black p-4 rounded">
          <h2 className="font-semibold">Port Analysis</h2>
          {loadingPort && (
            <div className="w-full bg-gray-200 h-2 rounded mt-2 overflow-hidden">
              <div className="bg-black h-2 animate-pulse w-full"></div>
            </div>
          )}
          {!loadingPort && (
            <>
              <p className="mt-2">Pontuação: {portAlerts.length}</p>
              <button type="button" className="underline text-sm" onClick={() => setShowPort(!showPort)}>
                Ver Detalhes
              </button>
              {showPort && (
                <ul className="list-disc list-inside text-sm mt-2">
                  {portAlerts.map((a, i) => (
                    <li key={i}>
                      <strong>{a.ip}:{a.porta}</strong> → {a.mensagem}
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>

        <div className="bg-[#ec008c] text-black p-4 rounded">
          <h2 className="font-semibold">Software Analysis</h2>
          {loadingSoft && (
            <div className="w-full bg-gray-200 h-2 rounded mt-2 overflow-hidden">
              <div className="bg-black h-2 animate-pulse w-full"></div>
            </div>
          )}
          {!loadingSoft && (
            <>
              <p className="mt-2">Pontuação: {softAlerts.length}</p>
              <button type="button" className="underline text-sm" onClick={() => setShowSoft(!showSoft)}>
                Ver Detalhes
              </button>
              {showSoft && (
                <ul className="list-disc list-inside text-sm mt-2">
                  {softAlerts.map((a, i) => (
                    <li key={i}>
                      <strong>{a.ip}:{a.porta}</strong> → {a.software} vulnerável a {a.cve_id} (CVSS {a.cvss})
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>

        <div className="bg-[#ec008c] text-black p-4 rounded">
          <h2 className="font-semibold">Outros Módulos</h2>
          <p className="mt-2">Em desenvolvimento...</p>
        </div>
      </div>
    </form>
  );
}
