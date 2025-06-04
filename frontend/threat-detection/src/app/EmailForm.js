'use client';
import { useState } from 'react';

export default function EmailForm() {
  const [email, setEmail] = useState('');
  const [loadingPort, setLoadingPort] = useState(false);
  const [loadingSoft, setLoadingSoft] = useState(false);
  const [portAlerts, setPortAlerts] = useState([]);
  const [softAlerts, setSoftAlerts] = useState([]);
  const [showPort, setShowPort] = useState(false);
  const [showSoft, setShowSoft] = useState(false);
  const [showCards, setShowCards] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setShowCards(true);
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
      </form>
      {showCards && (
        <div className="mt-6 w-full max-w-2xl space-y-4">
          <div className="bg-[#ec008c] text-black p-4 rounded shadow">
            <h2 className="font-semibold">Port Analysis</h2>
            {loadingPort ? (
              <p className="animate-pulse">Calculando risco...</p>
            ) : (
              <>
                <p className="mt-2">Score: {portAlerts.length}</p>
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
                <p className="mt-2">Score: {softAlerts.length}</p>
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
          <div className="bg-[#ec008c] text-black p-4 rounded shadow">
            <h2 className="font-semibold">Outros Módulos</h2>
            <p className="italic">Em breve...</p>
          </div>
        </div>
      )}
    </div>
  );
}