'use client';
import { useState, useRef } from 'react';
import ScoreGauge from './Gauge';

export default function EmailForm() {
  const [email, setEmail] = useState('');
  const [loadingPort, setLoadingPort] = useState(false);
  const [loadingSoft, setLoadingSoft] = useState(false);
  const [portAlerts, setPortAlerts] = useState([]);
  const [softAlerts, setSoftAlerts] = useState([]);
  const [portScore, setPortScore] = useState(0);
  const [softScore, setSoftScore] = useState(0);
  const [finalScore, setFinalScore] = useState(null);
  const [showCards, setShowCards] = useState(false);
  const [selectedDetail, setSelectedDetail] = useState(null);
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
    setSelectedDetail(null);
    jobRef.current = null;

    try {
      const res = await fetch('/api/port-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
      if (err.name !== 'AbortError') alert('Erro ao conectar ao backend');
      setLoadingPort(false);
      setLoadingSoft(false);
    }
  };

  const pollSoftware = async (id) => {
    if (!id || jobRef.current !== id) return;
    try {
      const res = await fetch(`/api/software-analysis/${id}`);
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
      await fetch('/api/cancel-current', { method: 'POST' });
    } catch (e) {}
    if (id) {
      try {
        await fetch(`/api/cancel/${id}`, { method: 'POST' });
      } catch (e) {}
    }
    jobRef.current = null;
    setLoadingPort(false);
    setLoadingSoft(false);
    setShowCards(false);
    setSelectedDetail(null);
  };

  return (
    <div className="w-full flex flex-col items-center gap-y-6 px-4">
      {finalScore !== null && (
        <div className="bg-[#1a1a1a] text-white p-6 rounded-2xl shadow-lg w-full max-w-xl text-center border-t-4 border-[#ec008c]">
          <h2 className="text-lg font-bold mb-2 tracking-wide uppercase">Score Final</h2>
          <ScoreGauge value={finalScore} />
        </div>
      )}

      <form
        onSubmit={handleSubmit}
        className="bg-[#1a1a1a] p-6 rounded-2xl shadow-lg flex flex-col md:flex-row gap-4 w-full max-w-xl text-white border border-[#ec008c]"
      >
        <input
          type="email"
          placeholder="usuario@empresa.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="flex-1 p-3 rounded bg-white text-black outline-none"
          required
        />
        <div className="flex flex-col md:flex-row gap-2">
          <button
            type="submit"
            className="bg-[#ec008c] hover:bg-pink-600 text-white px-4 py-2 rounded font-semibold"
            disabled={loadingPort || loadingSoft}
          >
            {loadingPort ? 'Analisando...' : 'Analisar'}
          </button>
          {(loadingPort || loadingSoft) && (
            <button
              type="button"
              className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded font-semibold"
              onClick={cancelJob}
            >
              Cancelar
            </button>
          )}
        </div>
      </form>

      {(loadingPort || loadingSoft) && (
        <div className="w-full max-w-xl h-2 bg-gray-700 rounded-full overflow-hidden">
          <div className="loading-bar h-full w-1/3 bg-pink-500 opacity-80 animate-slide" />
        </div>
      )}

      {showCards && (
        <>
          <div className="mt-6 w-full max-w-7xl flex flex-col md:flex-row md:flex-wrap md:justify-center gap-6">
            {/* Port Analysis */}
            <div className="bg-[#1a1a1a] text-white p-5 rounded-2xl shadow-lg w-full md:w-[48%] lg:w-[30%] border-l-4 border-[#ec008c]">
              <h2 className="text-xl font-semibold mb-2">Port Analysis</h2>
              {loadingPort ? (
                <p className="animate-pulse text-sm">Calculando risco...</p>
              ) : (
                <>
                  <p className="text-base">Score: {portScore}</p>
                  <button
                    type="button"
                    className="underline text-sm mt-2"
                    onClick={() =>
                      setSelectedDetail(selectedDetail === 'port' ? null : 'port')
                    }
                  >
                    Ver Detalhes
                  </button>
                </>
              )}
            </div>

            {/* Software Analysis */}
            <div className="bg-[#1a1a1a] text-white p-5 rounded-2xl shadow-lg w-full md:w-[48%] lg:w-[30%] border-l-4 border-[#ec008c]">
              <h2 className="text-xl font-semibold mb-2">Software Analysis</h2>
              {loadingSoft ? (
                <p className="animate-pulse text-sm">Calculando risco...</p>
              ) : (
                <>
                  <p className="text-base">Score: {softScore}</p>
                  <button
                    type="button"
                    className="underline text-sm mt-2"
                    onClick={() =>
                      setSelectedDetail(selectedDetail === 'soft' ? null : 'soft')
                    }
                  >
                    Ver Detalhes
                  </button>
                </>
              )}
            </div>

            {/* Placeholder */}
            <div className="bg-[#1a1a1a] text-white p-5 rounded-2xl shadow-lg w-full md:w-[48%] lg:w-[30%] border-l-4 border-[#ec008c]">
              <h2 className="text-xl font-semibold mb-2">Outros Módulos</h2>
              <p className="italic text-sm text-gray-400">Em breve...</p>
            </div>
          </div>

          {/* Caixa unificada de detalhes */}
          {selectedDetail && (
            <div className="mt-4 w-full max-w-7xl bg-[#1a1a1a] text-white p-6 rounded-2xl shadow-lg border border-[#ec008c]">
              <h2 className="text-xl font-bold mb-3">
                Detalhes: {selectedDetail === 'port' ? 'Port Analysis' : 'Software Analysis'}
              </h2>
              {selectedDetail === 'port' && portAlerts.length > 0 ? (
                <ul className="list-disc list-inside text-sm space-y-1">
                  {portAlerts.map((a, i) => (
                    <li key={i}>
                      <strong>{a.ip}:{a.porta}</strong> → {a.mensagem}
                    </li>
                  ))}
                </ul>
              ) : selectedDetail === 'soft' && softAlerts.length > 0 ? (
                <ul className="list-disc list-inside text-sm space-y-1">
                  {softAlerts.map((a, i) => (
                    <li key={i}>
                      <strong>{a.ip}:{a.porta}</strong> → {a.software} vulnerável a {a.cve_id} (CVSS {a.cvss})
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm italic text-gray-400">Nenhum alerta encontrado.</p>
              )}
            </div>
          )}
        </>
      )}

      {/* ESTILO DA BARRA ANIMADA */}
      <style jsx>{`
        @keyframes slide {
          0% {
            transform: translateX(-100%);
          }
          100% {
            transform: translateX(300%);
          }
        }
        .animate-slide {
          animation: slide 1.2s linear infinite;
        }
      `}</style>
    </div>
  );
}
