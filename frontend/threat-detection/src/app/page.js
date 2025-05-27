'use client'
import { useState } from 'react'
import axios from 'axios'

export default function Home() {
  const [email, setEmail] = useState('')
  const [resultado, setResultado] = useState('')
  const [carregando, setCarregando] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setCarregando(true)
    setResultado('')

    try {
      const response = await axios.post('http://localhost:5000/analisar', { email })
      setResultado(response.data.resultado)
    } catch (error) {
      setResultado('Erro ao conectar com o servidor.')
    }

    setCarregando(false)
  }

  return (
    <main className="min-h-screen flex flex-col items-center justify-center p-6">
      <h1 className="text-3xl font-bold mb-4">NGSX - Análise de Exposição</h1>
      <form onSubmit={handleSubmit} className="w-full max-w-md">
        <input
          type="email"
          placeholder="Digite seu e-mail corporativo"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="w-full p-2 border rounded mb-4"
          required
        />
        <button
          type="submit"
          className="w-full p-2 bg-black text-white rounded hover:bg-gray-800"
        >
          Iniciar Análise
        </button>
      </form>
      {carregando && <p className="mt-4">🔍 Analisando...</p>}
      {resultado && <pre className="mt-4 whitespace-pre-wrap">{resultado}</pre>}
    </main>
  )
}
