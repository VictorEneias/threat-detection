'use client';
import { useState, useRef } from 'react';

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000';

export default function EmailForm() {
  const [email, setEmail] = useState('');
  const [loadingPort, setLoadingPort] = useState(false);
  const [loadingSoft, setLoadingSoft] = useState(false);
  const [portAlerts, setPortAlerts] = useState([]);
  const [softAlerts, setSoftAlerts] = useState([]);
  const [portScore, setPortScore] = useState(0);
  const [softScore, setSoftScore] = useState(0);
  const [finalScore, setFinalScore] = useState(null);
  const [showPort, setShowPort] = useState(false);
  const [showSoft, setShowSoft] = useState(false);
  const [showCards, setShowCards] = useState(false);
  const jobRef = useRef(null);
  const abortRef = useRef(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    abortRef.current = new AbortController();
    setShowCards(true);
    setLoadingPort(true);
    setLoadingSoft(true);
    setPortAlerts([]);
    setSoftAlerts([]);
    setPortScore(0);
    setSoftScore(0);
    setFinalScore(null);
    jobRef.current = null;

    try {
      const res = await fetch(`${API_BASE}/api/port-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email }),
        signal: abortRef.current.signal
      });

      const data = await res.json();
      if (data.erro) {
        alert(`Erro: ${data.erro}`);
        setLoadingPort(false);
        setLoadingSoft(false);
        return;
      }
      setPortAlerts(data.alertas || []);
      setPortScore(data.port_score || 0);
      setLoadingPort(false);
      jobRef.current = data.job_id;
      pollSoftware(data.job_id);
    } catch (err) {
      if (err.name !== 'AbortError') {
        alert('Erro ao conectar ao backend');
      }
      setLoadingPort(false);
      setLoadingSoft(false);
    }
  };

  const pollSoftware = async (id) => {
    if (!id || jobRef.current !== id) return;
    try {
      const res = await fetch(`${API_BASE}/api/software-analysis/${id}`);
      const data = await res.json();
      if (data.alertas) {
        setSoftAlerts(data.alertas);
        setSoftScore(data.software_score || 0);
        setFinalScore(data.final_score ?? null);
        setLoadingSoft(false);
        jobRef.current = null;
      } else {
        setTimeout(() => pollSoftware(id), 2000);
      }
    } catch (e) {
      setTimeout(() => pollSoftware(id), 2000);
    }
  };

  const cancelJob = async () => {
    const id = jobRef.current;
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }
    try {
      await fetch(`${API_BASE}/api/cancel-current`, { method: 'POST' });
    } catch (e) {
      // ignore errors
    }
    if (id) {
      try {
        await fetch(`${API_BASE}/api/cancel/${id}`, { method: 'POST' });
      } catch (e) {
        // ignore errors
      }
    }
    jobRef.current = null;
    setLoadingPort(false);
    setLoadingSoft(false);
    setShowCards(false);
  };

  return (
    <div className="w-full flex flex-col items-center">
      <form onSubmit={handleSubmit} className="bg-[#ec008c] p-4 rounded-lg flex gap-2 w-full max-w-md">
        <input
          type="email"
          placeholder="usuario@empresa.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="flex-1 p-2 rounded text-black"
          required
        />
        <button
          type="submit"
          className="bg-black text-white px-4 py-2 rounded"
          disabled={loadingPort || loadingSoft}
        >
          {loadingPort ? 'Analisando...' : 'Analisar'}
        </button>
        {(loadingPort || loadingSoft) && (
          <button
            type="button"
            className="bg-black text-white px-4 py-2 rounded"
            onClick={cancelJob}
          >
            Cancelar
          </button>
        )}
      </form>
      {showCards && (
        <div className="mt-6 w-full max-w-2xl space-y-4">
          <div className="bg-[#ec008c] text-black p-4 rounded shadow">
            <h2 className="font-semibold">Port Analysis</h2>
            {loadingPort ? (
              <p className="animate-pulse">Calculando risco...</p>
            ) : (
              <>
                <p className="mt-2">Score: {portScore}</p>
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

          <div className="bg-[#ec008c] text-black p-4 rounded shadow">
            <h2 className="font-semibold">Software Analysis</h2>
            {loadingSoft ? (
              <p className="animate-pulse">Calculando risco...</p>
            ) : (
              <>
                <p className="mt-2">Score: {softScore}</p>
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

          {finalScore !== null && (
            <div className="bg-[#ec008c] text-black p-4 rounded shadow">
              <h2 className="font-semibold">Score Final</h2>
              <p className="mt-2 text-xl font-bold">{finalScore}</p>
            </div>
          )}
          <div className="bg-[#ec008c] text-black p-4 rounded shadow">
            <h2 className="font-semibold">Outros Módulos</h2>
            <p className="italic">Em breve...</p>
          </div>
        </div>
      )}
    </div>
  );
}
