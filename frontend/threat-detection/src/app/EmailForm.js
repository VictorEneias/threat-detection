'use client';
import { useState } from 'react';

export default function EmailForm() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [resultado, setResultado] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResultado('');

    try {
      const res = await fetch('http://localhost:8000/api/analisar', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });

      const data = await res.json();  // <- resposta do backend
      if (data.erro) {
        setResultado(`Erro: ${data.erro}`);
      } else if (data.alertas && data.alertas.length > 0) {
        const texto = data.alertas.map(a => `${a.ip}:${a.porta} → ${a.mensagem}`).join('\n');
        setResultado(
          <>
            <h2 className="text-lg font-semibold mb-2">🔒 Alertas de Segurança:</h2>
            <ul className="list-disc list-inside space-y-1 text-sm">
            {data.alertas.map((a, i) => (
                <li key={i}>
                <strong>{a.ip}:{a.porta}</strong> → {a.mensagem}
                </li>
            ))}
            </ul>
          </>
        );
      }     else if (data.mensagem) {
        setResultado(data.mensagem);
      } else {
        setResultado("Análise concluída, sem alertas.");
      }

    } catch (err) {
      alert('Erro ao conectar ao backend');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <input
        type="email"
        placeholder="asdas@aluno.unb.br"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="border border-black p-2 w-full rounded text-gray-800"
        required
      />
      <button
        type="submit"
        className="bg-blue-600 text-white px-4 py-2 rounded"
        disabled={loading}
      >
        {loading ? 'Analisando...' : 'Analisar'}
      </button>

      {resultado && (
        <div className="mt-4 bg-gray-200 p-3 rounded text-black">
          {resultado}
        </div>
      )}
    </form>
  );
}
